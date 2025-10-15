// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.19;

import {
    Id,
    IMorphoStaticTyping,
    IMorphoBase,
    MarketParams,
    Position,
    Market,
    Authorization,
    Signature
} from "./interfaces/IMorpho.sol";
import {
    IMorphoLiquidateCallback,
    IMorphoRepayCallback,
    IMorphoSupplyCallback,
    IMorphoSupplyCollateralCallback,
    IMorphoFlashLoanCallback
} from "./interfaces/IMorphoCallbacks.sol";
import {IIrm} from "./interfaces/IIrm.sol";
import {IERC20} from "./interfaces/IERC20.sol";
import {IOracle} from "./interfaces/IOracle.sol";

import {ErrorsLib} from "./libraries/ErrorsLib.sol";
import {EventsLib} from "./libraries/EventsLib.sol";
import "./libraries/ConstantsLib.sol";
import {MathLib, WAD} from "./libraries/MathLib.sol";
import {MarketParamsLib} from "./libraries/MarketParamsLib.sol";
import {UtilsLib} from "./libraries/UtilsLib.sol";
import {SharesMathLib} from "./libraries/SharesMathLib.sol";
import {SafeTransferLib} from "./libraries/SafeTransferLib.sol";

contract Morpho is IMorphoStaticTyping {
    using MathLib for uint128;
    using MathLib for uint256;
    using UtilsLib for uint256;
    using SharesMathLib for uint256;
    using MarketParamsLib for MarketParams;
    using SafeTransferLib for IERC20;

    bytes32 public immutable DOMAIN_SEPARATOR;

    address public owner;
    address public feeRecipient;

    mapping(address => bool) public isIrmEnabled;
    mapping(uint256 => bool) public isLltvEnabled;
    mapping(Id => Market) public market;
    mapping(address => mapping(address => bool)) public isAuthorized;
    mapping(address => uint256) public nonce;
    mapping(Id => MarketParams) public idToMarketParams;
    mapping(Id => mapping(address => Position)) public position;

    constructor(address newOwner) {
        require(newOwner != address(0), ErrorsLib.ZERO_ADDRESS);

        DOMAIN_SEPARATOR = keccak256(abi.encode(DOMAIN_TYPEHASH, block.chainid, address(this)));
        owner = newOwner;

        emit EventsLib.SetOwner(newOwner);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, ErrorsLib.NOT_OWNER);
        _;
    }

    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != owner, ErrorsLib.ALREADY_SET);

        owner = newOwner;

        emit EventsLib.SetOwner(newOwner);
    }

    function enableIrm(address irm) external onlyOwner {
        require(!isIrmEnabled[irm], ErrorsLib.ALREADY_SET);

        isIrmEnabled[irm] = true;

        emit EventsLib.EnableIrm(irm);
    }

    function enableLltv(uint256 lltv) external onlyOwner {
        require(!isLltvEnabled[lltv], ErrorsLib.ALREADY_SET);
        require(lltv < WAD, ErrorsLib.MAX_LLTV_EXCEEDED);

        isLltvEnabled[lltv] = true;

        emit EventsLib.EnableLltv(lltv);
    }

    function setFee(MarketParams memory marketParams, uint256 newFee) external onlyOwner {
        Id id = marketParams.id();
        require(market[id].lastUpdate != 0, ErrorsLib.MARKET_NOT_CREATED);
        require(newFee != market[id].fee, ErrorsLib.ALREADY_SET);
        require(newFee <= MAX_FEE, ErrorsLib.MAX_FEE_EXCEEDED);

        // TODO: core function
        _accrueInterest(marketParams, id);

        market[id].fee = uint128(newFee);

        emit EventsLib.SetFee(id, newFee);
    }

    function setFeeRecipient(address newFeeRecipient) external onlyOwner {
        require(newFeeRecipient != feeRecipient, ErrorsLib.ALREADY_SET);

        feeRecipient = newFeeRecipient;

        emit EventsLib.SetFeeRecipient(newFeeRecipient);
    }

    function createMarket(MarketParams memory marketParams) external {
        Id id = marketParams.id();
        require(isIrmEnabled[marketParams.irm], ErrorsLib.IRM_NOT_ENABLED);
        require(isLltvEnabled[marketParams.lltv], ErrorsLib.LLTV_NOT_ENABLED);
        require(market[id].lastUpdate == 0, ErrorsLib.MARKET_ALREADY_CREATED);

        market[id].lastUpdate = uint128(block.timestamp);
        idToMarketParams[id] = marketParams;

        emit EventsLib.CreateMarket(id, marketParams);

        if (marketParams.irm != address(0)) IIrm(marketParams.irm).borrowRate(marketParams, market[id]);
    }

    function supply(
        MarketParams memory marketParams,
        uint256 assets,
        uint256 shares,
        address onBehalf,
        bytes calldata data
    ) external returns (uint256, uint256) {
        Id id = marketParams.id();
        require(market[id].lastUpdate != 0, ErrorsLib.MARKET_NOT_CREATED);
        require(UtilsLib.exactlyOneZero(assets, shares), ErrorsLib.INCONSISTENT_INPUT);
        require(onBehalf != address(0), ErrorsLib.ZERO_ADDRESS);

        _accrueInterest(marketParams, id);

        if (assets > 0) shares = assets.toSharesDown(market[id].totalSupplyAssets, market[id].totalSupplyShares);
        else assets = shares.toAssetsUp(market[id].totalSupplyAssets, market[id].totalSupplyShares);

        position[id][onBehalf].supplyShares += shares;
        market[id].totalSupplyShares += shares.toUint128();
        market[id].totalSupplyAssets += assets.toUint128();

        emit EventsLib.Supply(id, msg.sender, onBehalf, assets, shares);

        if (data.length > 0) IMorphoSupplyCallback(msg.sender).onMorphoSupply(assets, data);

        IERC20(marketParams.loanToken).safeTransferFrom(msg.sender, address(this), assets);

        return (assets, shares);
    }

    function withdraw(
        MarketParams memory marketParams,
        uint256 assets,
        uint256 shares,
        address onBehalf,
        address receiver
    ) external returns (uint256, uint256) {
        Id id = marketParams.id();
        require(market[id].lastUpdate != 0, ErrorsLib.MARKET_NOT_CREATED);
        require(UtilsLib.exactlyOneZero(assets, shares), ErrorsLib.INCONSISTENT_INPUT);
        require(receiver != address(0), ErrorsLib.ZERO_ADDRESS);
        require(_isSenderAuthorized(onBehalf), ErrorsLib.UNAUTHORIZED);

        _accrueInterest(marketParams, id);

        if (assets > 0) shares = assets.toSharesUp(market[id].totalSupplyAssets, market[id].totalSupplyShares);
        else assets = shares.toAssetsDown(market[id].totalSupplyAssets, market[id].totalSupplyShares);

        // The deduction quota underflow will be automatically reverted due to the arithmetic check in Solidity 0.8
        position[id][onBehalf].supplyShares -= shares;
        market[id].totalSupplyShares -= shares.toUint128();
        market[id].totalSupplyAssets -= assets.toUint128();

        require(market[id].totalBorrowAssets <= market[id].totalSupplyAssets, ErrorsLib.INSUFFICIENT_LIQUIDITY);

        emit EventsLib.Withdraw(id, msg.sender, onBehalf, receiver, assets, shares);

        IERC20(marketParams.loanToken).safeTransfer(receiver, assets);

        return (assets, shares);
    }

    function borrow(
        MarketParams memory marketParams,
        uint256 assets,
        uint256 shares,
        address onBehalf,
        address receiver
    ) external returns (uint256, uint256) {
        Id id = marketParams.id();
        require(market[id].lastUpdate != 0, ErrorsLib.MARKET_NOT_CREATED);
        require(UtilsLib.exactlyOneZero(assets, shares), ErrorsLib.INCONSISTENT_INPUT);
        require(receiver != address(0), ErrorsLib.ZERO_ADDRESS);
        require(_isSenderAuthorized(onBehalf), ErrorsLib.UNAUTHORIZED);

        _accrueInterest(marketParams, id);

        if (assets > 0) shares = assets.toSharesUp(market[id].totalBorrowAssets, market[id].totalBorrowShares);
        else assets = shares.toAssetsDown(market[id].totalBorrowAssets, market[id].totalBorrowShares);

        position[id][onBehalf].borrowShares += shares.toUint128();
        market[id].totalBorrowShares += shares.toUint128();
        market[id].totalBorrowAssets += assets.toUint128();

        require(_isHealthy(marketParams, id, onBehalf), ErrorsLib.INSUFFICIENT_COLLATERAL);
        require(market[id].totalBorrowAssets <= market[id].totalSupplyAssets, ErrorsLib.INSUFFICIENT_LIQUIDITY);

        emit EventsLib.Borrow(id, msg.sender, onBehalf, receiver, assets, shares);

        IERC20(marketParams.loanToken).safeTransfer(receiver, assets);

        return (assets, shares);
    }

    function setAuthorization(address authorized, bool newIsAuthorized) external {
        require(newIsAuthorized != isAuthorized[msg.sender][authorized], ErrorsLib.ALREADY_SET);

        isAuthorized[msg.sender][authorized] = newIsAuthorized;

        emit EventsLib.SetAuthorization(msg.sender, msg.sender, authorized, newIsAuthorized);
    }

    function setAuthorizationWithSig(Authorization memory authorization, Signature calldata signature) external {
        require(block.timestamp <= authorization.deadline, ErrorsLib.SIGNATURE_EXPIRED);
        require(authorization.nonce == nonce[authorization.authorizer]++, ErrorsLib.INVALID_NONCE);

        bytes32 hashStruct = keccak256(abi.encode(AUTHORIZATION_TYPEHASH, authorization));
        bytes32 digest = keccak256(bytes.concat("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signatory = ecrecover(digest, signature.v, signature.r, signature.s);

        require(signatory != address(0) && authorization.authorizer == signatory, ErrorsLib.INVALID_SIGNATURE);

        emit EventsLib.IncrementNonce(msg.sender, authorization.authorizer, authorization.nonce);

        isAuthorized[authorization.authorizer][authorization.authorized] = authorization.isAuthorized;

        emit EventsLib.SetAuthorization(msg.sender, authorization.authorizer, authorization.authorized, authorization.isAuthorized);
    }

    function _isSenderAuthorized(address onBehalf) internal view returns (bool) {
        return msg.sender == onBehalf || isAuthorized[onBehalf][msg.sender];
    }

    function accrueInterest(MarketParams memory marketParams) external {
        Id id = marketParams.id();
        require(market[id].lastUpdate != 0, ErrorsLib.MARKET_NOT_CREATED);

        _accrueInterest(marketParams, id);
    }

    function _accrueInterest(MarketParams memory marketParams, Id id) internal {
        uint256 elapsed = block.timestamp - market[id].lastUpdate;
        if (elapsed == 0) return;

        if (marketParams.irm != address(0)) {
            uint256 borrowRate = IIrm(marketParams.irm).borrowRate(marketParams, market[id]);
            uint256 interest = market[id].totalBorrowAssets.wMulDown(borrowRate.wTaylorCompounded(elapsed));
            market[id].totalBorrowAssets += interest.toUint128();
            market[id].totalSupplyAssets += interest.toUint128();

            uint256 feeShares;
            if (market[id].fee != 0) {
                uint256 feeAmount = interest.wMulDown(market[id].fee);
                // newShares = assets * (totalShares / totalAssets)
                feeShares = feeAmount.toSharesDown(market[id].totalSupplyAssets - feeAmount, market[id].totalSupplyShares);
                position[id][feeRecipient].supplyShares += feeShares;
                market[id].totalSupplyShares += feeShares.toUint128();
            }

            emit EventsLib.AccrueInterest(id, borrowRate, interest, feeShares);
        }

        market[id].lastUpdate = uint128(block.timestamp);
    }

    function _isHealthy(MarketParams memory marketParams, Id id, address borrower) internal view returns (bool) {
        if (position[id][borrower].borrowShares == 0) return true;

        uint256 collateralPrice = IOracle(marketParams.oracle).price();

        return _isHealthy(marketParams, id, borrower, collateralPrice);
    }

    function _isHealthy(MarketParams memory marketParams, Id id, address borrower, uint256 collateralPrice)
        internal
        view
        returns (bool)
    {
        uint256 borrowed = uint256(position[id][borrower].borrowShares).toAssetsUp(
            market[id].totalBorrowAssets, market[id].totalBorrowShares
        );
        uint256 maxBorrow = uint256(position[id][borrower].collateral).mulDivDown(collateralPrice, ORACLE_PRICE_SCALE)
            .wMulDown(marketParams.lltv);

        return maxBorrow >= borrowed;
    }
}