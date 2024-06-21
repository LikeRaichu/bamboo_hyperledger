package hyperledger

import (
	"fmt"
	"sync"

	"github.com/gitferry/bamboo/blockchain"
	"github.com/gitferry/bamboo/config"
	"github.com/gitferry/bamboo/crypto"
	"github.com/gitferry/bamboo/election"
	"github.com/gitferry/bamboo/log"
	"github.com/gitferry/bamboo/message"
	"github.com/gitferry/bamboo/node"
	"github.com/gitferry/bamboo/pacemaker"
	"github.com/gitferry/bamboo/types"
)

const FORK = "fork"

type HyperLedger struct {
	node.Node
	election.Election
	pm              *pacemaker.Pacemaker
	lastVotedView   types.View
	preferredView   types.View
	highQC          *blockchain.QC
	bc              *blockchain.BlockChain
	committedBlocks chan *blockchain.Block
	forkedBlocks    chan *blockchain.Block
	bufferedQCs     map[crypto.Identifier]*blockchain.QC
	bufferedBlocks  map[types.View]*blockchain.Block
	mu              sync.Mutex
}

func NewHyperLedger(
	node node.Node,
	pm *pacemaker.Pacemaker,
	elec election.Election,
	committedBlocks chan *blockchain.Block,
	forkedBlocks chan *blockchain.Block) *HyperLedger {
	hl := new(HyperLedger)
	hl.Node = node
	hl.Election = elec
	hl.pm = pm
	hl.bc = blockchain.NewBlockchain(config.GetConfig().N())
	hl.bufferedBlocks = make(map[types.View]*blockchain.Block)
	hl.bufferedQCs = make(map[crypto.Identifier]*blockchain.QC)
	hl.highQC = &blockchain.QC{View: 0}
	hl.committedBlocks = committedBlocks
	hl.forkedBlocks = forkedBlocks
	return hl
}

func (hl *HyperLedger) ProcessBlock(block *blockchain.Block) error {
	log.Debugf("[%v] is processing block from %v, view: %v, id: %x", hl.ID(), block.Proposer.Node(), block.View, block.ID)
	curView := hl.pm.GetCurView()
	if block.Proposer != hl.ID() {
		blockIsVerified, _ := crypto.PubVerify(block.Sig, crypto.IDToByte(block.ID), block.Proposer)
		if !blockIsVerified {
			log.Warningf("[%v] received a block with an invalid signature", hl.ID())
		}
	}
	if block.View > curView+1 {
		//	buffer the block
		hl.bufferedBlocks[block.View-1] = block
		log.Debugf("[%v] the block is buffered, id: %x", hl.ID(), block.ID)
		return nil
	}
	if block.QC != nil {
		hl.updateHighQC(block.QC)
	} else {
		return fmt.Errorf("the block should contain a QC")
	}
	// does not have to process the QC if the replica is the proposer
	if block.Proposer != hl.ID() {
		hl.processCertificate(block.QC)
	}
	curView = hl.pm.GetCurView()
	if block.View < curView {
		log.Warningf("[%v] received a stale proposal from %v", hl.ID(), block.Proposer)
		return nil
	}
	if !hl.Election.IsLeader(block.Proposer, block.View) {
		return fmt.Errorf("received a proposal (%v) from an invalid leader (%v)", block.View, block.Proposer)
	}
	hl.bc.AddBlock(block)
	// process buffered QC
	qc, ok := hl.bufferedQCs[block.ID]
	if ok {
		hl.processCertificate(qc)
		delete(hl.bufferedQCs, block.ID)
	}

	shouldVote, err := hl.votingRule(block)
	if err != nil {
		log.Errorf("[%v] cannot decide whether to vote the block, %w", hl.ID(), err)
		return err
	}
	if !shouldVote {
		log.Debugf("[%v] is not going to vote for block, id: %x", hl.ID(), block.ID)
		return nil
	}
	vote := blockchain.MakeVote(block.View, hl.ID(), block.ID)
	// vote is sent to the next leader
	voteAggregator := hl.FindLeaderFor(block.View + 1)
	if voteAggregator == hl.ID() {
		log.Debugf("[%v] vote is sent to itself, id: %x", hl.ID(), vote.BlockID)
		hl.ProcessVote(vote)
	} else {
		log.Debugf("[%v] vote is sent to %v, id: %x", hl.ID(), voteAggregator, vote.BlockID)
		hl.Send(voteAggregator, vote)
	}
	b, ok := hl.bufferedBlocks[block.View]
	if ok {
		_ = hl.ProcessBlock(b)
		delete(hl.bufferedBlocks, block.View)
	}
	return nil
}

func (hl *HyperLedger) ProcessVote(vote *blockchain.Vote) {
	log.Debugf("[%v] is processing the vote, block id: %x", hl.ID(), vote.BlockID)
	if vote.Voter != hl.ID() {
		voteIsVerified, err := crypto.PubVerify(vote.Signature, crypto.IDToByte(vote.BlockID), vote.Voter)
		if err != nil {
			log.Warningf("[%v] Error in verifying the signature in vote id: %x", hl.ID(), vote.BlockID)
			return
		}
		if !voteIsVerified {
			log.Warningf("[%v] received a vote with invalid signature. vote id: %x", hl.ID(), vote.BlockID)
			return
		}
	}
	isBuilt, qc := hl.bc.AddVote(vote)
	if !isBuilt {
		log.Debugf("[%v] not sufficient votes to build a QC, block id: %x", hl.ID(), vote.BlockID)
		return
	}
	qc.Leader = hl.ID()
	// buffer the QC if the block has not been received
	_, err := hl.bc.GetBlockByID(qc.BlockID)
	if err != nil {
		hl.bufferedQCs[qc.BlockID] = qc
		return
	}
	hl.processCertificate(qc)
}

func (hl *HyperLedger) ProcessRemoteTmo(tmo *pacemaker.TMO) {
	log.Debugf("[%v] is processing tmo from %v", hl.ID(), tmo.NodeID)
	hl.processCertificate(tmo.HighQC)
	isBuilt, tc := hl.pm.ProcessRemoteTmo(tmo)
	if !isBuilt {
		return
	}
	log.Debugf("[%v] a tc is built for view %v", hl.ID(), tc.View)
	hl.processTC(tc)
}

func (hl *HyperLedger) ProcessLocalTmo(view types.View) {
	hl.pm.AdvanceView(view)
	tmo := &pacemaker.TMO{
		View:   view + 1,
		NodeID: hl.ID(),
		HighQC: hl.GetHighQC(),
	}
	hl.Broadcast(tmo)
	hl.ProcessRemoteTmo(tmo)
}

func (hl *HyperLedger) MakeProposal(view types.View, payload []*message.Transaction) *blockchain.Block {
	qc := hl.forkChoice()
	block := blockchain.MakeBlock(view, qc, qc.BlockID, payload, hl.ID())
	return block
}

func (hl *HyperLedger) forkChoice() *blockchain.QC {
	var choice *blockchain.QC
	if !hl.IsByz() || config.GetConfig().Strategy != FORK {
		return hl.GetHighQC()
	}
	//	create a fork by returning highQC's parent's QC
	parBlockID := hl.GetHighQC().BlockID
	parBlock, err := hl.bc.GetBlockByID(parBlockID)
	if err != nil {
		log.Warningf("cannot get parent block of block id: %x: %w", parBlockID, err)
	}
	if parBlock.QC.View < hl.preferredView {
		choice = hl.GetHighQC()
	} else {
		choice = parBlock.QC
	}
	// to simulate TC's view
	choice.View = hl.pm.GetCurView() - 1
	return choice
}

func (hl *HyperLedger) processTC(tc *pacemaker.TC) {
	if tc.View < hl.pm.GetCurView() {
		return
	}
	hl.pm.AdvanceView(tc.View)
}

func (hl *HyperLedger) GetHighQC() *blockchain.QC {
	hl.mu.Lock()
	defer hl.mu.Unlock()
	return hl.highQC
}

func (hl *HyperLedger) GetChainStatus() string {
	chainGrowthRate := hl.bc.GetChainGrowth()
	blockIntervals := hl.bc.GetBlockIntervals()
	return fmt.Sprintf("[%v] The current view is: %v, chain growth rate is: %v, ave block interval is: %v", hl.ID(), hl.pm.GetCurView(), chainGrowthRate, blockIntervals)
}

func (hl *HyperLedger) updateHighQC(qc *blockchain.QC) {
	hl.mu.Lock()
	defer hl.mu.Unlock()
	if qc.View > hl.highQC.View {
		hl.highQC = qc
	}
}

func (hl *HyperLedger) processCertificate(qc *blockchain.QC) {
	log.Debugf("[%v] is processing a QC, block id: %x", hl.ID(), qc.BlockID)
	if qc.View < hl.pm.GetCurView() {
		return
	}
	if qc.Leader != hl.ID() {
		quorumIsVerified, _ := crypto.VerifyQuorumSignature(qc.AggSig, qc.BlockID, qc.Signers)
		if quorumIsVerified == false {
			log.Warningf("[%v] received a quorum with invalid signatures", hl.ID())
			return
		}
	}
	if hl.IsByz() && config.GetConfig().Strategy == FORK && hl.IsLeader(hl.ID(), qc.View+1) {
		hl.pm.AdvanceView(qc.View)
		return
	}
	err := hl.updatePreferredView(qc)
	if err != nil {
		hl.bufferedQCs[qc.BlockID] = qc
		log.Debugf("[%v] a qc is buffered, view: %v, id: %x", hl.ID(), qc.View, qc.BlockID)
		return
	}
	hl.pm.AdvanceView(qc.View)
	hl.updateHighQC(qc)
	if qc.View < 3 {
		return
	}
	ok, block, _ := hl.commitRule(qc)
	if !ok {
		return
	}
	// forked blocks are found when pruning
	committedBlocks, forkedBlocks, err := hl.bc.CommitBlock(block.ID, hl.pm.GetCurView())
	if err != nil {
		log.Errorf("[%v] cannot commit blocks, %w", hl.ID(), err)
		return
	}
	for _, cBlock := range committedBlocks {
		hl.committedBlocks <- cBlock
	}
	for _, fBlock := range forkedBlocks {
		hl.forkedBlocks <- fBlock
	}
}

func (hl *HyperLedger) votingRule(block *blockchain.Block) (bool, error) {
	if block.View <= 2 {
		return true, nil
	}
	parentBlock, err := hl.bc.GetParentBlock(block.ID)
	if err != nil {
		return false, fmt.Errorf("cannot vote for block: %w", err)
	}
	if (block.View <= hl.lastVotedView) || (parentBlock.View < hl.preferredView) {
		return false, nil
	}
	return true, nil
}

func (hl *HyperLedger) commitRule(qc *blockchain.QC) (bool, *blockchain.Block, error) {
	parentBlock, err := hl.bc.GetParentBlock(qc.BlockID)
	if err != nil {
		return false, nil, fmt.Errorf("cannot commit any block: %w", err)
	}
	grandParentBlock, err := hl.bc.GetParentBlock(parentBlock.ID)
	if err != nil {
		return false, nil, fmt.Errorf("cannot commit any block: %w", err)
	}
	if ((grandParentBlock.View + 1) == parentBlock.View) && ((parentBlock.View + 1) == qc.View) {
		return true, grandParentBlock, nil
	}
	return false, nil, nil
}

func (hl *HyperLedger) updateLastVotedView(targetView types.View) error {
	if targetView < hl.lastVotedView {
		return fmt.Errorf("target view is lower than the last voted view")
	}
	hl.lastVotedView = targetView
	return nil
}

func (hl *HyperLedger) updatePreferredView(qc *blockchain.QC) error {
	if qc.View <= 2 {
		return nil
	}
	_, err := hl.bc.GetBlockByID(qc.BlockID)
	if err != nil {
		return fmt.Errorf("cannot update preferred view: %w", err)
	}
	grandParentBlock, err := hl.bc.GetParentBlock(qc.BlockID)
	if err != nil {
		return fmt.Errorf("cannot update preferred view: %w", err)
	}
	if grandParentBlock.View > hl.preferredView {
		hl.preferredView = grandParentBlock.View
	}
	return nil
}
