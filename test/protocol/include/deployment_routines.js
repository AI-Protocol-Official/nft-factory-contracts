// Both Truffle and Hardhat with Truffle make instances of web3 and artifacts available in the global scope

// ACL token features and roles
const {
	FEATURE_ALL,
	ROLE_TOKEN_CREATOR,
} = require("../../include/features_roles");


/**
 * Deploys Whitelabel ERC721 token with all the features enabled
 *
 * @param a0 smart contract owner, super admin
 * @param name ERC721 name, optional, default value "Whitelabel NFT"
 * @param symbol ERC721 symbol, optional, default value "WFT"
 * @returns WhitelabelNFT instance
 */
async function whitelabel_erc721_deploy(a0, name, symbol) {
	// deploy the token
	const token = await whitelabel_erc721_deploy_restricted(a0, name, symbol);

	// enable all permissions on the token
	await token.updateFeatures(FEATURE_ALL, { from: a0 });

	// return the reference
	return token;
}

/**
 * Deploys Whitelabel ERC721 token with no features enabled
 *
 * @param a0 smart contract owner, super admin
 * @param name ERC721 name, optional, default value "Whitelabel NFT"
 * @param symbol ERC721 symbol, optional, default value "WFT"
 * @returns WhitelabelNFT instance
 */
async function whitelabel_erc721_deploy_restricted(a0, name = "Whitelabel NFT", symbol = "WFT") {
	// smart contracts required
	const WhitelabelNFT = artifacts.require("./WhitelabelNFT");

	// deploy and return the reference to instance
	return await WhitelabelNFT.new(name, symbol, { from: a0 });
}



/**
 * Deploys OpenSeaFactory with no features enabled, and no required roles set up
 *
 * Requires a valid PersonalityPodERC721 and ProxyRegistry instance addresses to be specified
 *
 * @param a0 smart contract owner, super admin
 * @param range_bounds an array defining token ID ranges for each option
 * @param persona_addr PersonalityPodERC721 token OpenSeaFactory is going to mint, required
 * @param proxy_registry_addr OpenSea proxy registry address
 * @returns OpenSeaFactory instance
 */
async function os_factory_deploy_pure(a0, range_bounds, persona_addr, proxy_registry_addr) {
	// smart contracts required
	const OpenSeaFactory = artifacts.require("./OpenSeaFactoryImpl");

	// deploy and return the reference to instance
	return await OpenSeaFactory.new(persona_addr, proxy_registry_addr, range_bounds, { from: a0 });
}


/**
 * Deploys PersonalityDrop with no features enabled, and no roles set up
 *
 * Requires a valid MintableERC721 instance address to be specified
 *
 * @param a0 smart contract owner, super admin
 * @param nft_addr MintableERC721 token Airdrop is going to mint, required
 * @returns PersonalityDrop instance
 */
async function nft_drop_deploy_pure(a0, nft_addr) {
	// smart contracts required
	const PersonalityDrop = artifacts.require("./ERC721Drop");

	// deploy and return the reference to instance
	return await PersonalityDrop.new(nft_addr, { from: a0 });
}


/**
 * Deploys NFTFactory with all features enabled, and all required roles set up
 *
 * @param a0 smart contract owner, super admin
 * @param nft_address address of the deployed ERC721 contract to enable minting for
 * @returns NFTFactory, ERC721 instances
 */
async function nft_factory_deploy(a0, nft_address) {
	// smart contracts required
	const WhitelabelNFT = artifacts.require("./WhitelabelNFT");

	// link/deploy the contracts
	const nft = nft_address ? await WhitelabelNFT.at(nft_address) : await whitelabel_erc721_deploy(a0);
	const factory = await nft_factory_deploy_restricted(a0);

	// enable features and roles
	await factory.updateFeatures(FEATURE_ALL, { from: a0 });
	await nft.updateRole(factory.address, ROLE_TOKEN_CREATOR, { from: a0 });

	// return all the linked/deployed instances
	return { factory, nft };
}

/**
 * Deploys NFTFactory with no features enabled, and no roles set up
 *
 * @param a0 smart contract owner, super admin
 * @returns NFTFactory instance
 */
async function nft_factory_deploy_restricted(a0) {
	// smart contracts required
	const NFTFactory = artifacts.require("./NFTFactory");

	// deploy and return the reference to instance
	return await NFTFactory.new({ from: a0 });
}

/**
 * Deploys NFTFactory with all features enabled, and all required roles set up
 *
 * @param a0 smart contract owner, super admin
 * @param nft_address address of the deployed ERC721 contract to enable minting for
 * @param hardcap total supply hardcap
 * @returns NFTFactory, ERC721 instances
 */
async function nft_factory_v2_deploy(a0, nft_address, hardcap = 10_000) {
	// smart contracts required
	const WhitelabelNFT = artifacts.require("./WhitelabelNFT");

	// link/deploy the contracts
	const nft = nft_address ? await WhitelabelNFT.at(nft_address) : await whitelabel_erc721_deploy(a0);
	const factory = await nft_factory_v2_deploy_restricted(a0, hardcap);

	// enable features and roles
	await factory.updateFeatures(FEATURE_ALL, { from: a0 });
	await nft.updateRole(factory.address, ROLE_TOKEN_CREATOR, { from: a0 });

	// return all the linked/deployed instances
	return { factory, nft };
}

/**
 * Deploys NFTFactory with no features enabled, and no roles set up
 *
 * @param a0 smart contract owner, super admin
 * @param hardcap total supply hardcap
 * @returns NFTFactory instance
 */
async function nft_factory_v2_deploy_restricted(a0, hardcap = 10_000) {
	// smart contracts required
	const NFTFactory = artifacts.require("./NFTFactoryV2");

	// deploy and return the reference to instance
	return await NFTFactory.new(hardcap, { from: a0 });
}

/**
 * Deploys NFTFactory with all features enabled, and all required roles set up
 *
 * @param a0 smart contract owner, super admin
 * @param nft_address address of the deployed ERC721 contract to enable minting for
 * @param hardcap total mint hardcap
 * @returns NFTFactory, ERC721 instances
 */
async function nft_factory_v3_deploy(a0, nft_address, hardcap = 10_000) {
	// smart contracts required
	const WhitelabelNFT = artifacts.require("./WhitelabelNFT");

	// link/deploy the contracts
	const nft = nft_address ? await WhitelabelNFT.at(nft_address) : await whitelabel_erc721_deploy(a0);
	const factory = await nft_factory_v3_deploy_restricted(a0, hardcap);

	// enable features and roles
	await factory.updateFeatures(FEATURE_ALL, { from: a0 });
	await nft.updateRole(factory.address, ROLE_TOKEN_CREATOR, { from: a0 });

	// return all the linked/deployed instances
	return { factory, nft };
}

/**
 * Deploys NFTFactory with no features enabled, and no roles set up
 *
 * @param a0 smart contract owner, super admin
 * @param hardcap total mint hardcap
 * @returns NFTFactory instance
 */
async function nft_factory_v3_deploy_restricted(a0, hardcap = 10_000) {
	// smart contracts required
	const NFTFactory = artifacts.require("./NFTFactoryV3");

	// deploy and return the reference to instance
	return await NFTFactory.new(hardcap, { from: a0 });
}

// export public deployment API
module.exports = {
	whitelabel_erc721_deploy,
	whitelabel_erc721_deploy_restricted,
	os_factory_deploy_pure,
	nft_drop_deploy_pure,
	nft_factory_deploy,
	nft_factory_deploy_restricted,
	nft_factory_v2_deploy,
	nft_factory_v2_deploy_restricted,
	nft_factory_v3_deploy,
	nft_factory_v3_deploy_restricted,
};
