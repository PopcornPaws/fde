// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { BN254 } from "./BN254.sol";
import { Types } from "./Types.sol";
import { Constants } from "./Constants.sol";


// We could also have an almost identical contract that supports the Paillier-encryption scheme 
contract FDE is BN254 {

    struct agreedPurchase {
        uint256 timeOut; // The protocol after this timestamp, simply aborts and returns funds.
        uint256 agreedPrice;
        Types.G1Point sellerPubKey;
        bool ongoingPurchase;
        bool fundsLocked;
        bool secretKeySent;
    }

    // We assume that for a given seller-buyer pair, there is only a single purchase at any given time
    // Maps seller (server addresses) to buyer (client addresses) which in turn are mapped to tx details
    mapping(address => mapping(address => agreedPurchase)) public orderBook; // Privacy is out of scope for now
    mapping(address => uint256) balances; //stores the Eth balances of sellers

    // Events
    event BroadcastPubKey(address indexed _seller, address indexed _buyer, uint256 _pubKeyX, uint256 _timeOut, uint256 _agreedPrice);
    event BroadcastSecKey(address indexed _seller, address indexed _buyer, uint256 _secKey);

    constructor (
    ) {
    }

    // Agreed price could be set by the contract akin to Uniswap whereby price would be dynamically changing
    // according to a constant product formula given the current number of sellers and buyers (assuming 
    // that each tx in the orderBook has the same volume)
    function sellerSendsPubKey(
        uint256 _timeOut,
        uint256 _agreedPrice,
        uint256 _pubKeyX,
        uint256 _pubKeyY,
        address _buyer
    ) public  {
        require(!orderBook[msg.sender][_buyer].ongoingPurchase, "There can only be one purchase per buyer-seller pair!");
        orderBook[msg.sender][_buyer].timeOut = _timeOut;
        orderBook[msg.sender][_buyer].agreedPrice = _agreedPrice;
        Types.G1Point memory _sellerPubKey = Types.G1Point(_pubKeyX, _pubKeyY);
        orderBook[msg.sender][_buyer].sellerPubKey = _sellerPubKey;
        orderBook[msg.sender][_buyer].ongoingPurchase = true;

        emit BroadcastPubKey(msg.sender, _buyer, _pubKeyX, _timeOut, _agreedPrice); 
    }

    // If buyer agrees to the details of the purchase, then it locks the corresponding amount of money.
    function buyerLockPayment(
         address _seller
    ) public payable {
        agreedPurchase memory order = orderBook[_seller][msg.sender];

        require(!order.secretKeySent, "Secret keys have been already revealed!");
        require(!order.fundsLocked, "Funds have been already locked!");
        require(msg.value == order.agreedPrice, "The transferred money does not match the agreed price!");

        orderBook[_seller][msg.sender].fundsLocked = true;
    }

    function sellerSendsSecKey(
        uint256 _secKey,
        address _buyer
    ) public {
        agreedPurchase memory order = orderBook[msg.sender][_buyer];

        require(!order.secretKeySent, "Secret key has been already revealed.");
        require(mul(P1(),_secKey).x == order.sellerPubKey.x, "Invalid secret key has been provided by the seller!");

        // this case is problematic for the seller, because they already revealed the secret key
        // but it is important for the health of the protocol that we don't increase their balance
        // if the funds have not been locked
        require(order.fundsLocked, "Funds have not been locked yet!");

        orderBook[msg.sender][_buyer].secretKeySent = true;
        orderBook[msg.sender][_buyer].ongoingPurchase = false;

        balances[msg.sender] += order.agreedPrice;

        // There is no need to store the secret key in storage
        emit BroadcastSecKey(msg.sender, _buyer, _secKey);
    }

    // This function allocates funds to the server from previous accrued purchase incomes
    function withdrawPayment(
        
    ) public {
        uint256 balance = balances[msg.sender];
        if (balance != 0) {
            // We reset the balance to zero before the transfer to prevent reentrancy attacks
            balances[msg.sender] = 0;

            // forward all gas to the recipient
            (bool success, ) = payable(msg.sender).call{value: balance}("");

            // revert on error
            require(success, "Transfer failed.");
        }
    }

    // Buyer can withdraw its money if seller does not reveal the correct secret key.
    function withdrawPaymentAfterTimout(
        address _seller
    ) public {
        agreedPurchase memory order = orderBook[_seller][msg.sender];

        require(!order.secretKeySent, "The encryption secret key has already been sent by the seller!");
        require(block.timestamp >= order.timeOut, "The seller has still time to provide the encryption secret key!");
        require(order.fundsLocked, "Funds have not been locked yet!");

        orderBook[_seller][msg.sender].ongoingPurchase = false;

        // forward all gas to the recipient
        (bool success, ) = payable(msg.sender).call{value: order.agreedPrice}("");

        // revert on error
        require(success, "Transfer failed.");
    }
}
