// AI Protocol NFTFactory: NFT Minting via Helper tests

// Zeppelin test helpers
const {
	BN,
	balance,
	constants,
	expectEvent,
	expectRevert,
} = require("@openzeppelin/test-helpers");
const {
	ZERO_ADDRESS,
	ZERO_BYTES32,
	MAX_UINT256,
} = constants;

// Chai test helpers
const {
	assert,
	expect,
} = require("chai");

// helper functions in use
const {
	expectEventInTransaction,
} = require("../include/helper");

// BN utils
const {
	random_bn,
} = require("../include/bn_utils");

// NFT Factory EIP712 helpers
const {
	default_deadline,
	NFTFactoryEIP712,
} = require("./include/nft_factory_eip712");
const {
	eip712_mint,
	eip712_cancel,
} = new NFTFactoryEIP712("NFTFactoryV2");

// ACL features and roles
const {
	not,
	FEATURE_MINTING_WITH_AUTH,
	ROLE_FACTORY_MINTER,
} = require("../include/features_roles");

// deployment routines in use
const {
	nft_factory_v2_deploy,
	nft_factory_v2_deploy_restricted,
} = require("./include/deployment_routines");

// run NFT factory tests
contract("NFT Factory: minting an NFT via helper smart contract", function(accounts) {
	// extract accounts to be used:
	// A0 – special default zero account accounts[0] used by Truffle, reserved
	// a0 – deployment account having all the permissions, reserved
	// H0 – initial token holder account
	// a1, a2,... – working accounts to perform tests on
	const [A0, a0, H0, a1, a2, a3, a4, a5] = accounts;

	describe("factory deployment", function() {
		it("fails if total supply hardcap is not set", async function() {
			await expectRevert(nft_factory_v2_deploy_restricted(a0, 0), "hardcap is not set");
		});
		describe("succeeds otherwise", function() {
			let factory;
			beforeEach(async function() {
				factory = await nft_factory_v2_deploy_restricted(a0, 13);
			});
			it("hardcap is set correctly", async function() {
				expect(await factory.totalSupplyHardcap()).to.be.bignumber.that.equals("13");
			});
		});
	});
	describe("when factory is deployed with default hardcap (10,000)", function() {
		let factory, nft;
		beforeEach(async function() {
			({factory, nft} = await nft_factory_v2_deploy(a0));
		});

		function mint_test_suite(mint_fn, we, they, tokenId, nonce) {
			it("reverts if NFT contract address is not specified (zero)", async function() {
				await expectRevert(
					mint_fn(ZERO_ADDRESS, they, tokenId, {from: we}),
					"ERC721 instance addr is not set"
				);
			});
			it("reverts if NFT recipient address is not specified (zero)", async function() {
				await expectRevert(
					mint_fn(nft.address, ZERO_ADDRESS, tokenId, {from: we}),
					"NFT receiver addr is not set"
				);
			});
			it("reverts if NFT ID is not specified (zero)", async function() {
				await expectRevert(
					mint_fn(nft.address, they, 0, {from: we}),
					"token ID is not set"
				);
			});

			describe("succeeds otherwise", function() {
				let receipt;
				beforeEach(async function() {
					receipt = await mint_fn(nft.address, they, tokenId, {from: we});
				});
				it('"Minted" event is emitted on the Factory', async function() {
					await expectEvent(receipt, "Minted", {
						erc721Address: nft.address,
						to: they,
						tokenId: tokenId + "",
					});
				});
				it('"Transfer" event is emitted on the ERC721 contract', async function() {
					await expectEvent.inTransaction(receipt.tx, nft, "Transfer", {
						_from: ZERO_ADDRESS,
						_to: they,
						_tokenId: tokenId + "",
					});
				});
				it("token with the ID specified exists", async function() {
					expect(await nft.exists(tokenId)).to.be.true;
				});
				it("token with the ID specified belongs to an expected owner", async function() {
					expect(await nft.ownerOf(tokenId)).to.be.equal(they);
				});
				if(nonce) {
					it('"AuthorizationUsed" event is emitted', async function() {
						await expectEvent(receipt, "AuthorizationUsed", {authorizer: we, nonce})
					});
				}
			});
		}

		describe("direct minting (we pay gas)", function() {
			const we = a1;
			const they = a2;
			const tokenId = 1;
			beforeEach(async function() {
				await factory.updateRole(we, ROLE_FACTORY_MINTER, {from: a0});
			});
			mint_test_suite(async (...args) => await factory.mint(...args), we, they, tokenId);
		});
		describe("minting with authorization (they pay gas)", function() {
			// create empty account with known private key
			const w = web3.eth.accounts.create();

			// prepare some signature related defaults
			const we = w.address;
			const operator = a1;
			const they = a2;
			const tokenId = 1;
			const nonce = ZERO_BYTES32;
			let validAfter, validBefore;
			beforeEach(async function() {
				({validAfter, validBefore} = await default_deadline());
				await factory.updateRole(we, ROLE_FACTORY_MINTER, {from: a0});
			});

			async function mint_with_auth(contract = nft.address, to = they, token_id = tokenId) {
				const {v, r, s} = await eip712_mint(factory.address, contract, to, token_id, validAfter, validBefore, nonce, w.privateKey);
				return await factory.mintWithAuthorization(contract, to, token_id, validAfter, validBefore, nonce, v, r, s, {from: operator});
			}

			async function cancel_with_auth(_nonce = nonce) {
				const {v, r, s} = await eip712_cancel(factory.address, we, _nonce, w.privateKey);
				return await factory.cancelAuthorization(we, _nonce, v, r, s, {from: operator});
			}

			it("reverts when MintWithAuthorization signature is invalid", async function() {
				let {v, r, s} = await eip712_mint(
					factory.address,
					nft.address,
					they,
					tokenId,
					validAfter,
					validBefore,
					nonce,
					w.privateKey,
				);
				// break the signature
				v = 26; // valid values are 27 and 28
				await expectRevert(factory.mintWithAuthorization(
					nft.address,
					they,
					tokenId,
					validAfter,
					validBefore,
					nonce,
					v,
					r,
					s,
					{from: operator},
				), "invalid signature");
			});
			it("reverts when MintWithAuthorization signature belongs to unauthorized account", async function() {
				// override signing account, so the signature becomes invalid
				const w = web3.eth.accounts.create();
				const {v, r, s} = await eip712_mint(
					factory.address,
					nft.address,
					they,
					tokenId,
					validAfter,
					validBefore,
					nonce,
					w.privateKey,
				);
				await expectRevert(factory.mintWithAuthorization(
					nft.address,
					they,
					tokenId,
					validAfter,
					validBefore,
					nonce,
					v,
					r,
					s,
					{from: operator},
				), "access denied");
			});
			it("reverts when MintWithAuthorization signature is not yet valid", async function() {
				// make signature not yet valid
				validAfter = validBefore;
				const {v, r, s} = await eip712_mint(
					factory.address,
					nft.address,
					they,
					tokenId,
					validAfter,
					validBefore,
					nonce,
					w.privateKey,
				);
				await expectRevert(factory.mintWithAuthorization(
					nft.address,
					they,
					tokenId,
					validAfter,
					validBefore,
					nonce,
					v,
					r,
					s,
					{from: operator},
				), "signature not yet valid");
			});
			it("reverts when MintWithAuthorization signature is expired", async function() {
				// make signature expired
				validBefore = validAfter;
				const {v, r, s} = await eip712_mint(
					factory.address,
					nft.address,
					they,
					tokenId,
					validAfter,
					validBefore,
					nonce,
					w.privateKey,
				);
				await expectRevert(factory.mintWithAuthorization(
					nft.address,
					they,
					tokenId,
					validAfter,
					validBefore,
					nonce,
					v,
					r,
					s,
					{from: operator},
				), "signature expired");
			});
			it("reverts when MintWithAuthorization signature nonce is invalid (already used)", async function() {
				// invalidate the nonce
				await cancel_with_auth(nonce);
				const {v, r, s} = await eip712_mint(
					factory.address,
					nft.address,
					they,
					tokenId,
					validAfter,
					validBefore,
					nonce,
					w.privateKey,
				);
				await expectRevert(factory.mintWithAuthorization(
					nft.address,
					they,
					tokenId,
					validAfter,
					validBefore,
					nonce,
					v,
					r,
					s,
					{from: operator},
				), "invalid nonce");
			});

			mint_test_suite(mint_with_auth, we, they, tokenId, nonce);
		});
		describe("nonce cancellation and authorization state", function() {
			const we = a1;
			const nonce = ZERO_BYTES32;
			describe("when nonce is not yet used", function() {
				it("authorizationState is false", async function() {
					expect(await factory.authorizationState(we, nonce)).to.be.false;
				});
				describe("cancelAuthorization succeeds", function() {
					let receipt;
					beforeEach(async function() {
						receipt = await factory.methods["cancelAuthorization(bytes32)"](nonce, {from: we});
					});
					it('"AuthorizationCanceled" event is emitted', async function() {
						await expectEvent(receipt, "AuthorizationCanceled", {authorizer: we, nonce});
					});
					it("authorizationState becomes true", async function() {
						expect(await factory.authorizationState(we, nonce)).to.be.true;
					});
				});
				describe("cancelAuthorization with authorization succeeds", function() {
					// create empty account with known private key
					const w = web3.eth.accounts.create();

					// prepare some signature related defaults
					const we = w.address;
					const operator = a1;
					const they = a2;
					const tokenId = 1;
					const nonce = ZERO_BYTES32;
					let validAfter, validBefore;
					beforeEach(async function() {
						({validAfter, validBefore} = await default_deadline());
					});

					async function cancel_with_auth(authorizer = we, _nonce = nonce) {
						const {v, r, s} = await eip712_cancel(factory.address, authorizer, _nonce, w.privateKey);
						return await factory.cancelAuthorization(authorizer, _nonce, v, r, s, {from: operator});
					}

					it("fails if wrong signer is used", async function() {
						await expectRevert(cancel_with_auth(operator), "invalid signature");
					});
					describe("succeeds otherwise", function() {
						let receipt;
						beforeEach(async function() {
							receipt = await cancel_with_auth();
						});
						it('"AuthorizationCanceled" event is emitted', async function() {
							await expectEvent(receipt, "AuthorizationCanceled", {authorizer: we, nonce});
						});
						it("authorizationState becomes true", async function() {
							expect(await factory.authorizationState(we, nonce)).to.be.true;
						});
					});
				});
			});
			describe("when nonce is already used", function() {
				beforeEach(async function() {
					await factory.methods["cancelAuthorization(bytes32)"](nonce, {from: we});
				});
				it("it cannot be used anymore", async function() {
					await expectRevert(factory.methods["cancelAuthorization(bytes32)"](nonce, {from: we}), "invalid nonce");
				});
			});
		});
		describe("ACL", function() {
			// create empty account with known private key
			const w = web3.eth.accounts.create();

			// prepare some signature related defaults
			const we = w.address;
			const operator = a1;
			const they = a2;
			const tokenId = 1;
			const nonce = ZERO_BYTES32;
			let validAfter, validBefore;
			beforeEach(async function() {
				({validAfter, validBefore} = await default_deadline());
				await factory.updateRole(we, ROLE_FACTORY_MINTER, {from: a0});
			});

			async function mint(contract = nft.address, to = they, token_id = tokenId) {
				return factory.mint(contract, to, token_id, {from: operator});
			}

			async function mint_with_auth(contract = nft.address, to = they, token_id = tokenId) {
				const {v, r, s} = await eip712_mint(factory.address, contract, to, token_id, validAfter, validBefore, nonce, w.privateKey);
				return await factory.mintWithAuthorization(contract, to, token_id, validAfter, validBefore, nonce, v, r, s, {from: operator});
			}

			describe("when FEATURE_MINTING_WITH_AUTH is disabled", function() {
				beforeEach(async function() {
					await factory.updateFeatures(not(FEATURE_MINTING_WITH_AUTH), {from: a0});
				});
				it("mint with auth fails", async function() {
					await expectRevert(mint_with_auth(), "minting with auth is disabled");
				});
			});
			describe("when FEATURE_MINTING_WITH_AUTH is enabled", function() {
				beforeEach(async function() {
					await factory.updateFeatures(FEATURE_MINTING_WITH_AUTH, {from: a0});
				});
				it("mint with auth succeeds", async function() {
					await mint_with_auth();
				});
			});
			describe("when sender doesn't have ROLE_FACTORY_MINTER permission", function() {
				beforeEach(async function() {
					await factory.updateRole(operator, not(ROLE_FACTORY_MINTER), {from: a0});
				});
				it("mint fails", async function() {
					await expectRevert(mint(), "access denied");
				});
			});
			describe("when sender has ROLE_FACTORY_MINTER permission", function() {
				beforeEach(async function() {
					await factory.updateRole(operator, ROLE_FACTORY_MINTER, {from: a0});
				});
				it("mint", async function() {
					await mint();
				});
			});
			describe("when signer doesn't have ROLE_FACTORY_MINTER permission", function() {
				beforeEach(async function() {
					await factory.updateRole(we, not(ROLE_FACTORY_MINTER), {from: a0});
				});
				it("mint with auth fails", async function() {
					await expectRevert(mint_with_auth(), "access denied");
				});
			});
			describe("when signer has ROLE_FACTORY_MINTER permission", function() {
				beforeEach(async function() {
					await factory.updateRole(we, ROLE_FACTORY_MINTER, {from: a0});
				});
				it("mint with auth succeeds", async function() {
					await mint_with_auth();
				});
			});
		});
	});
	describe("when factory is deployed with lower hardcap (1)", function() {
		let factory, nft;
		beforeEach(async function() {
			({factory, nft} = await nft_factory_v2_deploy(a0, undefined, 1));
		});
		it("minting one NFT is possible", async function() {
			await factory.mint(nft.address, a1, 1, {from: a0});
		});
		describe("after one NFT is minted", function() {
			beforeEach(async function() {
				await factory.mint(nft.address, a1, 1, {from: a0});
			});
			it("minting another NFTs is not possible", async function() {
				await expectRevert(factory.mint(nft.address, a1, 2, {from: a0}), "hardcap reached");
			});
		});
	});
});
