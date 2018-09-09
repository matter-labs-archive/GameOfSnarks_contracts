pragma solidity ^0.4.24;

import {Pairing, Verifier} from "./BattleshipSnarkVerifier.sol";

contract BattleshipsGame {
    address public commitmentSender = msg.sender;
    uint256 public operatorsCollateral;
    uint256 public lastSubmittedCommitment;
    uint256 public lastGameNumber;
    uint256 public stakeSize = 1000000000000000000;
    uint64 public timeToAccept = uint64(30 minutes);
    enum GameSetupStage {
        StageProposed,
        StageResponded,
        StageAccepted,
        StageRefused
    }

    struct Game {
        address Player1;
        address Player2;
        bytes32 Player1Position;
        bytes32 Player2Position;
        bytes32 FirstMove;
        uint256 Nonce;
        uint256 Player1Score;
        uint256 Player2Score;
        bytes32 Player1Shots;
        bytes32 Player2Shots;
        address ToBlame;
        GameSetupStage Stage;
        uint64 PropositionTime;
    }

    event GameProposed(uint256 indexed _gameNumber, address indexed _anotherPlayer, bytes32 indexed _position);
    event GameResponded(uint256 indexed _gameNumber, bytes32 indexed _position);
    event GameRefused(uint256 indexed _gameNumber);
    event GameStarted(uint256 indexed _gameNumber);
    event CommitmentSubmitted(uint256 indexed _commitmentNumber, bytes32 indexed _commitment);

    mapping(uint256 => bytes32) commitments;
    mapping(uint256 => Game) games;

    constructor() payable public {
        require(msg.value > 0, "Operator should have a stake");
        operatorsCollateral = msg.value;
    }

    function() external {
        revert("Fallback function is not used");
    }

    function proposeGame(bytes32 myPosition, address anotherPlayer) payable public {
        require(msg.value == stakeSize, "Game should have a stake");
        lastGameNumber++;
        Game storage newGame = games[lastGameNumber];
        newGame.Player1 = msg.sender;
        newGame.Player2 = anotherPlayer;
        newGame.Player1Position = myPosition;
        newGame.PropositionTime = uint64(block.timestamp);
        newGame.Stage = GameSetupStage.StageProposed;
        emit GameProposed(lastGameNumber, anotherPlayer, myPosition);
    }

    function acceptProposal(uint256 gameNumber, bytes32 myPosition) payable public {
        require(msg.value == stakeSize, "Game should have a stake");
        Game storage newGame = games[gameNumber];
        require(newGame.Player2 == msg.sender, "Trying to accept another game");
        require(newGame.Stage == GameSetupStage.StageProposed, "Invalid game state to accept");
        require(newGame.PropositionTime + timeToAccept >= uint64(block.timestamp), "Too late to accept a game");
        newGame.Player2Position = myPosition;
        newGame.PropositionTime = uint64(block.timestamp);
        newGame.Stage = GameSetupStage.StageResponded;
        emit GameResponded(gameNumber, myPosition);
    }

    function refuseGame(uint256 gameNumber) public {
        Game storage newGame = games[gameNumber];
        if (newGame.Stage == GameSetupStage.StageResponded) {
            require(
                newGame.Player1 == msg.sender ||
                (newGame.Player2 == msg.sender && newGame.PropositionTime + timeToAccept <= uint64(block.timestamp)),
                "Conditions to refuse are not met");
            newGame.Stage == GameSetupStage.StageRefused;
            newGame.Player1.transfer(stakeSize);
            newGame.Player2.transfer(stakeSize);
        } else if (newGame.Stage == GameSetupStage.StageProposed) {
            require(newGame.PropositionTime + timeToAccept <= uint64(block.timestamp), "Too early to refuse");
            require(newGame.Player1 == msg.sender, "Only Player1 can refuse");
            newGame.Stage == GameSetupStage.StageRefused;
            newGame.Player1.transfer(stakeSize);
        } else {
            revert("Invalid state to refuse");
        }
        delete games[lastGameNumber];
        emit GameRefused(gameNumber);
    }

    function startGame(uint256 gameNumber, bytes32 firstMove) public {
        Game storage newGame = games[gameNumber];
        require(newGame.Player1 == msg.sender, "Only Player1 can accept");
        require(newGame.PropositionTime + timeToAccept >= uint64(block.timestamp), "Too late to accept");
        newGame.FirstMove = firstMove;
        emit GameStarted(gameNumber);
    }

    function sendCommitment(uint256 commitmentNumber, bytes32 commitment) public {
        require(msg.sender == commitmentSender, "Only an operator can send commitments");
        require(commitmentNumber == lastSubmittedCommitment + 1, "Invalid commitments order");
        commitments[commitmentNumber] = commitment;
        lastSubmittedCommitment++;
        emit CommitmentSubmitted(commitmentNumber, commitment);
    }

    // public params are Nonce, Nonce+1, Pl1Moves, Pl2Moves, Pl1Score, Pl2Score, NextShot
    // everything else is taken from the storage
    function proveInvalidMove(uint256 commitmentNumber, uint256 gameNumber, bytes merkleProof, uint256[18] zkSnarkProof, uint256[7] publicInputs, bytes32[3] signature) public {
        require(gameNumber <= lastGameNumber);
        Game storage existingGame = games[gameNumber];
        bytes32 messageHash = keccak256(abi.encodePacked(gameNumber, zkSnarkProof, publicInputs));
        address signer = ecrecover(messageHash, uint8(signature[0]), signature[1], signature[2]);
        uint256 nonce = publicInputs[0];
        if (nonce == 0) { //first round
            if (publicInputs[6] != uint256(existingGame.FirstMove)) {
                payOperatorsStake(msg.sender);
                return;
            }
        }
        if (nonce % 2 == 0 && signer != existingGame.Player2) {
            payOperatorsStake(msg.sender);
            return;
        } else if (nonce % 2 == 1 && signer != existingGame.Player1) {
            payOperatorsStake(msg.sender);
            return;
        }
        Verifier.Proof memory proof;
        proof.A = Pairing.G1Point(zkSnarkProof[0], zkSnarkProof[1]);
        proof.A_p = Pairing.G1Point(zkSnarkProof[2], zkSnarkProof[3]);
        proof.B = Pairing.G2Point([zkSnarkProof[4], zkSnarkProof[5]], [zkSnarkProof[6], zkSnarkProof[7]]);
        proof.B_p = Pairing.G1Point(zkSnarkProof[8], zkSnarkProof[9]);
        proof.C = Pairing.G1Point(zkSnarkProof[10], zkSnarkProof[11]);
        proof.C_p = Pairing.G1Point(zkSnarkProof[12], zkSnarkProof[13]);
        proof.H = Pairing.G1Point(zkSnarkProof[14], zkSnarkProof[15]);
        proof.K = Pairing.G1Point(zkSnarkProof[16], zkSnarkProof[17]);
        uint[] memory inputValues = new uint[](publicInputs.length);
        for(uint i = 0; i < publicInputs.length; i++){
            inputValues[i] = publicInputs[i];
        }

        uint isValidMove = Verifier.verify(inputValues, proof);
        if (isValidMove != 0) {
            payOperatorsStake(msg.sender);
            return;
        }
        revert("Proof is invalid");
    }

    function payOperatorsStake(address to) internal {
        require(operatorsCollateral != 0, "Operator should have money left");
        to.transfer(operatorsCollateral);
        operatorsCollateral = 0;
    }

}