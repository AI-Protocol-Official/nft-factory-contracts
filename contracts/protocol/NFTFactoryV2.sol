// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@lazy-sol/access-control/contracts/AccessControl.sol";
import "../interfaces/ERC721Spec.sol";
import "../interfaces/ERC721SpecExt.sol";
import "../lib/ECDSA.sol";

/**
 * @title AI Protocol NFT Factory
 *
 * @notice NFT Factory is a helper smart contract responsible for minting arbitrary NFTs
 *
 * @notice It supports two mechanisms:
 *      - minting delegation: authorized address executes mint function on the helper,
 *        and helper executes minting function on the target ERC721 contract as an internal transaction
 *      - meta transaction minting or minting with an authorization: authorized address signs
 *        the minting authorization message and any address executes mint function on the helper
 *
 * @notice Second mechanism allows to shift the gas costs for the transaction to any address
 *      (usually this is the NFT beneficiary - an address which receives an NFT)
 *
 * @dev The signature is constructed via EIP-712 similar to EIP-2612, or EIP-3009
 *
 * @dev Target ERC721 contract(s) must allow helper to mint the tokens, this should be configured
 *      as part of the deployment or setup processes
 *
 * @dev Version 2 (NFTFactoryV2) adds total supply limiting feature allowing to set the NFT total
 *     supply hardcap; factory stops minting when total supply of the ERC721 to mint reaches the hardcap
 */
contract NFTFactoryV2 is AccessControl {
	/**
	 * @notice Total Supply Hardcap affects factory capability to mint: once
	 *      target ERC721 total supply reaches the hardcap, factory stops minting it
	 *
	 * @dev The factory `mint` and `mintWithAuthorization` function throws
	 *      if target ERC721 `totalSupply` value is equal or bigger than `totalSupplyHardcap`
	 */
	uint256 public immutable totalSupplyHardcap;

	/**
	 * @dev A record of used nonces for EIP-712 transactions
	 *
	 * @dev A record of used nonces for signing/validating signatures
	 *      in `mintWithAuthorization` for every mint
	 *
	 * @dev Maps authorizer address => nonce => true/false (used unused)
	 */
	mapping(address => mapping(bytes32 => bool)) private usedNonces;

	/**
	 * @notice EIP-712 contract's domain separator,
	 *      see https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator
	 */
	bytes32 public immutable DOMAIN_SEPARATOR;

	/**
	 * @notice EIP-712 contract's domain typeHash,
	 *      see https://eips.ethereum.org/EIPS/eip-712#rationale-for-typehash
	 *
	 * @dev Note: we do not include version into the domain typehash/separator,
	 *      it is implied version is concatenated to the name field, like "NFTFactoryV2"
	 */
	// keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)")
	bytes32 public constant DOMAIN_TYPEHASH = 0x8cad95687ba82c2ce50e74f7b754645e5117c3a5bec8151c0726d5857980a866;

	/**
	 * @notice EIP-712 MintWithAuthorization struct typeHash,
	 *      see https://eips.ethereum.org/EIPS/eip-712#rationale-for-typehash
	 */
	// keccak256("MintWithAuthorization(address contract,address to,uint256 tokenId,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
	bytes32 public constant MINT_WITH_AUTHORIZATION_TYPEHASH =
		0x495835d970a03ff092657fca9abde67d34a0bb73a0bba258a5fa90c4ce4340f6;

	/**
	 * @notice EIP-712 CancelAuthorization struct typeHash,
	 *      see https://eips.ethereum.org/EIPS/eip-712#rationale-for-typehash
	 */
	// keccak256("CancelAuthorization(address authorizer,bytes32 nonce)")
	bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
		0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;

	/**
	 * @notice Enables meta transaction minting (minting with an authorization
	 *      via an EIP712 signature)
	 * @dev Feature FEATURE_MINTING_WITH_AUTH must be enabled in order for
	 *      `mintWithAuthorization()` function to succeed
	 */
	uint32 public constant FEATURE_MINTING_WITH_AUTH = 0x0000_0001;

	/**
	 * @notice Factory minter is responsible for creating (minting)
	 *      tokens to an arbitrary address
	 * @dev Role ROLE_FACTORY_MINTER allows minting tokens
	 *      (executing `mint` function)
	 */
	uint32 public constant ROLE_FACTORY_MINTER = 0x0001_0000;

	/**
	 * @dev Fired in mint() and mintWithAuthorization() after an NFT is minted
	 *
	 * @param erc721Address ERC721 contract address which was minted
	 * @param to an address NFT was minted to
	 * @param tokenId NFT ID which was minted
	 */
	event Minted(address indexed erc721Address, address indexed to, uint256 indexed tokenId);

	/**
	 * @dev Fired whenever the nonce gets used (ex.: `transferWithAuthorization`, `receiveWithAuthorization`)
	 *
	 * @param authorizer an address which has used the nonce
	 * @param nonce the nonce used
	 */
	event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

	/**
	 * @dev Fired whenever the nonce gets cancelled (ex.: `cancelAuthorization`)
	 *
	 * @dev Both `AuthorizationUsed` and `AuthorizationCanceled` imply the nonce
	 *      cannot be longer used, the only difference is that `AuthorizationCanceled`
	 *      implies no smart contract state change made (except the nonce marked as cancelled)
	 *
	 * @param authorizer an address which has cancelled the nonce
	 * @param nonce the nonce cancelled
	 */
	event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);

	/**
	 * Deploys the helper contract and initializes DOMAIN_SEPARATOR using the created smart contract address
	 *
	 * @param _totalSupplyHardcap ERC721 total supply limit, factory stops minting the ERC721
	 *      if its total supply (ERC721.totalSupply()) reaches the total supply had cap
	 */
	constructor(uint256 _totalSupplyHardcap) AccessControl(msg.sender, 0) {
		// build the EIP-712 contract domain separator, see https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator
		// note: we specify contract version in its name
		DOMAIN_SEPARATOR = keccak256(
			abi.encode(DOMAIN_TYPEHASH, keccak256(bytes("NFTFactoryV2")), block.chainid, address(this))
		);

		// verify the hardcap is set
		require(_totalSupplyHardcap != 0, "hardcap is not set");

		// set the total supply hardcap
		totalSupplyHardcap = _totalSupplyHardcap;
	}

	/**
	 * @notice Restricted access function to mint an NFT
	 *
	 * @dev Doesn't allow minting the token with ID zero
	 * @dev Requires an executor to have ROLE_MINTER permission
	 * @dev Requires target ERC721 contract to be mintable (`MintableERC721`)
	 * @dev Requires target ERC721 contract instance to allow minting via helper
	 *
	 * @param _targetErc721 target ERC721 contract instance to mint token on,
	 *      compatible with `MintableERC721`
	 * @param _to an address to mint token to
	 * @param _tokenId target ERC721 token ID to mint
	 */
	function mint(address _targetErc721, address _to, uint256 _tokenId) external {
		// delegate to _mint()
		__mint(msg.sender, _targetErc721, _to, _tokenId);
	}

	/**
	 * @dev Auxiliary internally used function to mint an NFT
	 *
	 * @dev Unsafe: doesn't verify real tx executor (msg.sender) permissions, but the permissions of
	 *      the address specified as an executor, must be kept private at all times
	 *
	 * @dev Doesn't allow minting the token with ID zero
	 * @dev Requires an executor to have ROLE_MINTER permission
	 * @dev Requires target ERC721 contract to be mintable (`MintableERC721`)
	 * @dev Requires target ERC721 contract instance to allow minting via helper
	 *
	 * @param _executor an address on which behalf the operation is executed,
	 *      this is usually `msg.sender` but this can be different address for
	 *      the EIP-712 like transactions (mint with authorization)
	 * @param _targetErc721 target ERC721 contract instance to mint token on,
	 *      compatible with `MintableERC721`
	 * @param _to an address to mint token to
	 * @param _tokenId target ERC721 token ID to mint
	 */
	function __mint(address _executor, address _targetErc721, address _to, uint256 _tokenId) private {
		// verify the access permission
		require(isOperatorInRole(_executor, ROLE_FACTORY_MINTER), "access denied");

		// verify the inputs
		require(_targetErc721 != address(0), "ERC721 instance addr is not set");
		require(_to != address(0), "NFT receiver addr is not set");
		require(_tokenId != 0, "token ID is not set");

		// verify if total supply hardcap is reached
		require(ERC721Enumerable(_targetErc721).totalSupply() < totalSupplyHardcap, "hardcap reached");

		// delegate to the target ERC721 contract
		MintableERC721(_targetErc721).safeMint(_to, _tokenId);

		// emit an event
		emit Minted(_targetErc721, _to, _tokenId);
	}

	/**
	 * @notice Executes a mint function with a signed authorization
	 *
	 * @param _targetErc721 target ERC721 contract instance to mint token on,
	 *      compatible with `MintableERC721`
	 * @param _to an address to mint token to
	 * @param _tokenId target ERC721 token ID to mint
	 * @param _validAfter signature valid after time (unix timestamp)
	 * @param _validBefore signature valid before time (unix timestamp)
	 * @param _nonce unique random nonce
	 * @param v the recovery byte of the signature
	 * @param r half of the ECDSA signature pair
	 * @param s half of the ECDSA signature pair
	 */
	function mintWithAuthorization(
		address _targetErc721,
		address _to,
		uint256 _tokenId,
		uint256 _validAfter,
		uint256 _validBefore,
		bytes32 _nonce,
		uint8 v,
		bytes32 r,
		bytes32 s
	) external {
		// ensure EIP-712 minting with authorization is enabled
		require(isFeatureEnabled(FEATURE_MINTING_WITH_AUTH), "minting with auth is disabled");

		// derive signer of the EIP712 MintWithAuthorization message
		address signer = __deriveSigner(
			abi.encode(MINT_WITH_AUTHORIZATION_TYPEHASH, _targetErc721, _to, _tokenId, _validAfter, _validBefore, _nonce),
			v,
			r,
			s
		);

		// perform message integrity and security validations
		require(block.timestamp > _validAfter, "signature not yet valid");
		require(block.timestamp < _validBefore, "signature expired");

		// use the nonce supplied (verify, mark as used, emit event)
		__useNonce(signer, _nonce, false);

		// delegate call to `_mint` - execute the logic required
		__mint(signer, _targetErc721, _to, _tokenId);
	}

	/**
	 * @notice Returns the state of an authorization, more specifically
	 *      if the specified nonce was already used by the address specified
	 *
	 * @dev Nonces are expected to be client-side randomly generated 32-byte data
	 *      unique to the authorizer's address
	 *
	 * @param _authorizer Authorizer's address
	 * @param _nonce Nonce of the authorization
	 * @return true if the nonce is used
	 */
	function authorizationState(address _authorizer, bytes32 _nonce) external view returns (bool) {
		// simply return the value from the mapping
		return usedNonces[_authorizer][_nonce];
	}

	/**
	 * @notice Cancels the authorization (using EIP-712 signature)
	 *
	 * @param _authorizer transaction authorizer
	 * @param _nonce unique random nonce to cancel (mark as used)
	 * @param v the recovery byte of the signature
	 * @param r half of the ECDSA signature pair
	 * @param s half of the ECDSA signature pair
	 */
	function cancelAuthorization(address _authorizer, bytes32 _nonce, uint8 v, bytes32 r, bytes32 s) external {
		// derive signer of the EIP712 ReceiveWithAuthorization message
		address signer = __deriveSigner(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, _authorizer, _nonce), v, r, s);

		// perform message integrity and security validations
		require(signer == _authorizer, "invalid signature");

		// cancel the nonce supplied (verify, mark as used, emit event)
		__useNonce(_authorizer, _nonce, true);
	}

	/**
	 * @notice Cancels the authorization
	 *
	 * @param _nonce unique random nonce to cancel (mark as used)
	 */
	function cancelAuthorization(bytes32 _nonce) public {
		// cancel the nonce supplied (verify, mark as used, emit event)
		__useNonce(msg.sender, _nonce, true);
	}

	/**
	 * @dev Auxiliary function to verify structured EIP712 message signature and derive its signer
	 *
	 * @param abiEncodedTypehash abi.encode of the message typehash together with all its parameters
	 * @param v the recovery byte of the signature
	 * @param r half of the ECDSA signature pair
	 * @param s half of the ECDSA signature pair
	 */
	function __deriveSigner(
		bytes memory abiEncodedTypehash,
		uint8 v,
		bytes32 r,
		bytes32 s
	) private view returns (address) {
		// build the EIP-712 hashStruct of the message
		bytes32 hashStruct = keccak256(abiEncodedTypehash);

		// calculate the EIP-712 digest "\x19\x01" ‖ domainSeparator ‖ hashStruct(message)
		bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

		// recover the address which signed the message with v, r, s
		address signer = ECDSA.recover(digest, v, r, s);

		// return the signer address derived from the signature
		return signer;
	}

	/**
	 * @dev Auxiliary function to use/cancel the nonce supplied for a given authorizer:
	 *      1. Verifies the nonce was not used before
	 *      2. Marks the nonce as used
	 *      3. Emits an event that the nonce was used/cancelled
	 *
	 * @dev Set `_cancellation` to false (default) to use nonce,
	 *      set `_cancellation` to true to cancel nonce
	 *
	 * @dev It is expected that the nonce supplied is a randomly
	 *      generated uint256 generated by the client
	 *
	 * @param _authorizer an address to use/cancel nonce for
	 * @param _nonce random nonce to use
	 * @param _cancellation true to emit `AuthorizationCancelled`, false to emit `AuthorizationUsed` event
	 */
	function __useNonce(address _authorizer, bytes32 _nonce, bool _cancellation) private {
		// verify nonce was not used before
		require(!usedNonces[_authorizer][_nonce], "invalid nonce");

		// update the nonce state to "used" for that particular signer to avoid replay attack
		usedNonces[_authorizer][_nonce] = true;

		// depending on the usage type (use/cancel)
		if (_cancellation) {
			// emit an event regarding the nonce cancelled
			emit AuthorizationCanceled(_authorizer, _nonce);
		} else {
			// emit an event regarding the nonce used
			emit AuthorizationUsed(_authorizer, _nonce);
		}
	}
}
