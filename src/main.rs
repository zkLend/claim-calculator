use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt::{Display, Formatter},
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
};

use anyhow::Result;
use bigdecimal::{
    num_bigint::{BigInt, Sign},
    BigDecimal,
};
use log::{debug, info, trace};
use serde::{Deserialize, Serialize};
use starknet::{
    core::{
        types::{
            requests::{CallRequest, GetStorageAtRequest},
            BlockId, EventFilter, Felt, FunctionCall,
        },
        utils::get_storage_var_address,
    },
    macros::{felt, selector},
    providers::{
        jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderRequestData, ProviderResponseData,
        Url,
    },
};

const MARKET_HALT_BLOCK: u64 = 1144392;

// TODO: once ZToken is halted update this block
const ZTOKEN_HALT_BLOCK: u64 = MARKET_HALT_BLOCK;

const MARKET_ADDRESS: Felt =
    felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05");
const ORACLE_ADDRESS: Felt =
    felt!("0x023fb3afbff2c0e3399f896dcf7400acf1a161941cfb386e34a123f228c62832");

const ETH: Asset = Asset {
    id: TokenId::ETH,
    is_affected: true,
    token_address: felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
    z_token_address: felt!("0x01b5bd713e72fdc5d63ffd83762f81297f6175a5e0a4771cdadbc1dd5fe72cb1"),
    z_token_deploy_block: 48669,
};

const USDC: Asset = Asset {
    id: TokenId::USDC,
    is_affected: true,
    token_address: felt!("0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8"),
    z_token_address: felt!("0x047ad51726d891f972e74e4ad858a261b43869f7126ce7436ee0b2529a98f486"),
    z_token_deploy_block: 48671,
};

const WBTC: Asset = Asset {
    id: TokenId::WBTC,
    is_affected: false,
    token_address: felt!("0x03fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac"),
    z_token_address: felt!("0x02b9ea3acdb23da566cee8e8beae3125a1458e720dea68c4a9a7a2d8eb5bbb4a"),
    z_token_deploy_block: 48673,
};

const USDT: Asset = Asset {
    id: TokenId::USDT,
    is_affected: true,
    token_address: felt!("0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8"),
    z_token_address: felt!("0x00811d8da5dc8a2206ea7fd0b28627c2d77280a515126e62baa4d78e22714c4a"),
    z_token_deploy_block: 48674,
};

const DAIV0: Asset = Asset {
    id: TokenId::DAIV0,
    is_affected: false,
    token_address: felt!("0x00da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3"),
    z_token_address: felt!("0x062fa7afe1ca2992f8d8015385a279f49fad36299754fb1e9866f4f052289376"),
    z_token_deploy_block: 48675,
};

const WSTETHV0: Asset = Asset {
    id: TokenId::WSTETHV0,
    is_affected: false,
    token_address: felt!("0x042b8f0484674ca266ac5d08e4ac6a3fe65bd3129795def2dca5c34ecc5f96d2"),
    z_token_address: felt!("0x0536aa7e01ecc0235ca3e29da7b5ad5b12cb881e29034d87a4290edbb20b7c28"),
    z_token_deploy_block: 335873,
};

const STRK: Asset = Asset {
    id: TokenId::STRK,
    is_affected: true,
    token_address: felt!("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"),
    z_token_address: felt!("0x06d8fa671ef84f791b7f601fa79fea8f6ceb70b5fa84189e3159d532162efc21"),
    z_token_deploy_block: 556817,
};

const ZEND: Asset = Asset {
    id: TokenId::ZEND,
    is_affected: false,
    token_address: felt!("0x00585c32b625999e6e5e78645ff8df7a9001cf5cf3eb6b80ccdd16cb64bd3a34"),
    z_token_address: felt!("0x02a28036ec5007c05c5611281a7d740c71a26d0305f7e9a4fa2f751d252a9f0d"),
    z_token_deploy_block: 622569,
};

const DAIV1: Asset = Asset {
    id: TokenId::DAIV1,
    is_affected: false,
    token_address: felt!("0x05574eb6b8789a91466f902c380d978e472db68170ff82a5b650b95a58ddf4ad"),
    z_token_address: felt!("0x04e9c97ac4bb76b743a59678432ca017fe263209a8b49e0618ecc73b9518db4a"),
    z_token_deploy_block: 637327,
};

const EKUBO: Asset = Asset {
    id: TokenId::EKUBO,
    is_affected: false,
    token_address: felt!("0x075afe6402ad5a5c20dd25e10ec3b3986acaa647b77e4ae24b0cbc9a54a27a87"),
    z_token_address: felt!("0x02f3add8ad0c2ab66568b5c2f315acf15636babf03f19e4dc8e3eacce43af9b2"),
    z_token_deploy_block: 671788,
};

const KSTRK: Asset = Asset {
    id: TokenId::KSTRK,
    is_affected: false,
    token_address: felt!("0x045cd05ee2caaac3459b87e5e2480099d201be2f62243f839f00e10dde7f500c"),
    z_token_address: felt!("0x07e475a3b2d64b97e48860bde4dad0255727c75f69aec760f90bd4d17e7f7d21"),
    z_token_deploy_block: 1015495,
};

const WSTETHV1: Asset = Asset {
    id: TokenId::WSTETHV1,
    is_affected: true,
    token_address: felt!("0x0057912720381af14b0e5c87aa4718ed5e527eab60b3801ebf702ab09139e38b"),
    z_token_address: felt!("0x05240577d1d546f1c241b9448a97664c555e4b0d716ed2ee4c43489467f24e29"),
    z_token_deploy_block: 1140817,
};

const ALL_ASSETS: [Asset; 12] = [
    ETH, USDC, WBTC, USDT, DAIV0, WSTETHV0, STRK, ZEND, DAIV1, EKUBO, KSTRK, WSTETHV1,
];

const REVENUE_ACCOUNT: Felt =
    felt!("0x0439d7ec4abbb69aaa8fa5acd9a682f118823f49f2542bc7673a9792ddff9fc2");

const TREASURY_ACCOUNTS: [Felt; 2] = [
    felt!("0x06a73619c58f9f8a98b91900a20c8eb02fdfded4ff6b8bd6722eba7b1f03ec0b"),
    felt!("0x05e77014d1d0a2bf6aa5659f9fc5bcac5ba3866d292e6b498e848366a1c6249f"),
];

const ATTACKER_ACCOUNTS: [Felt; 25] = [
    felt!("0x04d7191dc8eac499bac710dd368706e3ce76c9945da52535de770d06ce7d3b26"),
    felt!("0x07cfb0224f0c4cc5944dd2b3cca0128b601be186bb90ff058cf2f624797e7fb3"),
    felt!("0x07894ed6897529e1e07b10d7135ea026019a0755b99d907aacc7d25d4d726815"),
    felt!("0x042fef4933889c29bb8ebadb069ab9d4f84554af98927fe780bfd716f8b1f08c"),
    felt!("0x06195cc4bb308613ff8e5a1fc4d4155de0735b9bf5954bc3280ea3db2e2e77bc"),
    felt!("0x02b572515e72cc80828a2abf2b5a24a89e91d1c7af8e72231bda803c6ab1f740"),
    felt!("0x03b01804accaef97589c354221b80765f4af8cb90b55ec704bc3284b0ccc671f"),
    felt!("0x07d650bdcd646085ab786ce0b53a21d25dc761619bfed8fbb57c20c7743c361d"),
    felt!("0x04e0d319e53ddc0377b852fdc359abd12fda539e8c4f557d57bc01f61a9c9f42"),
    felt!("0x047fe199ff3f54e45fbb93c6fca812bba64b787c96fdda15734ccce0e5e4780b"),
    felt!("0x0122521852c1b19d785287305edd975fade2dcfad4741782b53310d1eb621704"),
    felt!("0x02199db864a191181ea76237fb74a6e6a820f21c06a95053e05fa54ec960e8c8"),
    felt!("0x04e54c220b7eecef91faa570f6a543e8cc45e9cdd793bef835422953817b8e0e"),
    felt!("0x05bea25dfd6a287cdee4158b18ba66f93efd42cfa2a1bbdfe832e8772430f89b"),
    felt!("0x045bcbfd8c05050c6642cea74d2f03c2fe6c508f739aff1e9cf0e53954804ac8"),
    felt!("0x07098dd1c1ff114397ae15a7c2f12a50b9fa436817692b31944fa6c2f0c831f5"),
    felt!("0x060253a7cf5b6af915555a0004924ddfa95fbb541c98b69e67723f4e5c0c459d"),
    felt!("0x014f5f484958759833e88d2619786cf014587b3886f3294d6fd6ea8ec0758fe8"),
    felt!("0x01de50bc88d656566f3bb33236a3de0712abc2152a65b5d31265e12145a18c14"),
    felt!("0x0693403417f5459497b779c9fa4986f7fd9d013b80e663c5ec2f6b2356e0e516"),
    felt!("0x00fbba395f7e94b7e74afc861ebba96fbbf554afa34c2021ed5dd5a357b065d7"),
    felt!("0x071f4d9dae30c93a1da92aaf259b04e07311f52431ed5c77755f0cbb6223c13c"),
    felt!("0x0105f2c0262c002181d9117f006909df968a2597e7f4ab4d37190e97aa60afca"),
    felt!("0x01ab0f3ab8a4231dea790297d9bd44c3b262b1506ae1eeff73081633f122315a"),
    felt!("0x0193da87dc0b317f8418ae0c8fb3e0301698ed2d1a4047191d4641ddabc1e2bf"),
];

const ACCUMULATOR_SCALE: Felt = felt!("1000000000000000000000000000");
const ACCUMULATOR_DECIMALS: u32 = 27;
const USD_DECIMALS: u32 = 8;

const EVENT_CHUNK_SIZE: u64 = 1000;
const USERS_FILE: &str = "./users.txt";
const BALANCES_FILE: &str = "./balances.json";
const POOL_DATA_FILE: &str = "./pools.json";
const CLAIMS_FILE: &str = "./claims.json";
const CLAIMS_REPORT_FILE: &str = "./claims_usd.csv";

#[derive(Debug, Clone, Copy)]
struct Asset {
    id: TokenId,
    is_affected: bool,
    token_address: Felt,
    z_token_address: Felt,
    z_token_deploy_block: u64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct UserBalances {
    collateral: BTreeMap<TokenId, Felt>,
    debt: BTreeMap<TokenId, Felt>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct PoolData {
    price: Felt,
    decimals: u32,
    balance: Felt,
    lending_accumulator: Felt,
    debt_accumulator: Felt,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct UserClaim {
    user: Felt,
    #[serde(flatten)]
    claim: Claim,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct Claim {
    withdrawable: BTreeMap<TokenId, Felt>,
    usd_shortfall: Felt,
}

struct PoolResult {
    token_id: TokenId,
    decimals: u32,
    price: Felt,
    is_affected: bool,
    balance: Felt,
    claim: Felt,
    usd_surplus: i128,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum TokenId {
    #[serde(rename = "eth")]
    ETH,
    #[serde(rename = "usdc")]
    USDC,
    #[serde(rename = "wbtc")]
    WBTC,
    #[serde(rename = "usdt")]
    USDT,
    #[serde(rename = "daiv0")]
    DAIV0,
    #[serde(rename = "wstethv0")]
    WSTETHV0,
    #[serde(rename = "strk")]
    STRK,
    #[serde(rename = "zend")]
    ZEND,
    #[serde(rename = "daiv1")]
    DAIV1,
    #[serde(rename = "ekubo")]
    EKUBO,
    #[serde(rename = "kstrk")]
    KSTRK,
    #[serde(rename = "wstethv1")]
    WSTETHV1,
}

impl Display for TokenId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ETH => write!(f, "eth"),
            Self::USDC => write!(f, "usdc"),
            Self::WBTC => write!(f, "wbtc"),
            Self::USDT => write!(f, "usdt"),
            Self::DAIV0 => write!(f, "daiv0"),
            Self::WSTETHV0 => write!(f, "wstethv0"),
            Self::STRK => write!(f, "strk"),
            Self::ZEND => write!(f, "zend"),
            Self::DAIV1 => write!(f, "daiv1"),
            Self::EKUBO => write!(f, "ekubo"),
            Self::KSTRK => write!(f, "kstrk"),
            Self::WSTETHV1 => write!(f, "wstethv1"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "claim_calculator=debug");
    }

    env_logger::init();

    let provider = JsonRpcClient::new(HttpTransport::new(match std::env::var("STARKNET_RPC") {
        Ok(var) => Url::parse(&var)?,
        Err(_) => Url::parse("https://starknet-mainnet.public.blastapi.io/rpc/v0_7").unwrap(),
    }));

    let users = generate_user_list(&provider).await?;
    let user_balances = fetch_user_balances(&provider, &users).await?;
    let pool_data = fetch_pool_data(&provider).await?;

    generate_claims(&user_balances, &pool_data)?;

    Ok(())
}

async fn generate_user_list<P: Provider>(provider: P) -> Result<Vec<Felt>> {
    if std::fs::exists(USERS_FILE)? {
        debug!("User list file found: {}", USERS_FILE);

        let mut input_file = File::open(USERS_FILE)?;
        let input_reader = BufReader::new(&mut input_file);

        let mut users = vec![];

        for line in input_reader.lines() {
            let line = line?;
            users.push(Felt::from_hex(&line)?);
        }

        info!("{} users loaded from file", users.len());

        Ok(users)
    } else {
        let mut users: BTreeSet<Felt> = BTreeSet::new();

        for asset in ALL_ASSETS {
            debug!("Scanning holders for {}", asset.id);

            let mut new_users_from_asset = 0;

            let mut cursor: Option<String> = None;

            let filter = EventFilter {
                from_block: Some(BlockId::Number(asset.z_token_deploy_block)),
                to_block: Some(BlockId::Number(ZTOKEN_HALT_BLOCK)),
                address: Some(asset.z_token_address),
                keys: Some(vec![vec![selector!("Transfer")]]),
            };

            loop {
                let mut new_users_from_iteration = 0;

                let chunk = provider
                    .get_events(filter.clone(), cursor, EVENT_CHUNK_SIZE)
                    .await?;

                for event in &chunk.events {
                    if event.keys.len() != 1 || event.keys[0] != selector!("Transfer") {
                        anyhow::bail!("unexpected event type");
                    }

                    for candidate in [event.data[0], event.data[1]] {
                        if candidate != Felt::ZERO && users.insert(candidate) {
                            new_users_from_iteration += 1;
                        }
                    }
                }

                new_users_from_asset += new_users_from_iteration;

                debug!(
                    "{} new users found from {} events{}",
                    new_users_from_iteration,
                    chunk.events.len(),
                    match chunk.events.last().map(|event| event.block_number) {
                        Some(Some(block_number)) =>
                            format!(" (to block {}/{})", block_number, ZTOKEN_HALT_BLOCK),
                        _ => "".to_owned(),
                    }
                );

                match chunk.continuation_token {
                    Some(new_cursor) => {
                        cursor = Some(new_cursor);
                    }
                    None => break,
                }
            }

            info!("{} new users found from {}", new_users_from_asset, asset.id);
        }

        info!("{} users found", users.len());

        let mut output_file = File::create(USERS_FILE)?;
        let mut output_writer = BufWriter::new(&mut output_file);

        for user in &users {
            writeln!(output_writer, "{:#064x}", user)?;
        }

        info!("User list persisted to {}", USERS_FILE);

        Ok(users.into_iter().collect())
    }
}

async fn fetch_user_balances<P: Provider>(
    provider: P,
    users: &[Felt],
) -> Result<BTreeMap<Felt, UserBalances>> {
    if std::fs::exists(BALANCES_FILE)? {
        debug!("Balance list file found: {}", BALANCES_FILE);

        let mut input_file = File::open(BALANCES_FILE)?;
        let mut input_reader = BufReader::new(&mut input_file);

        let user_balances: BTreeMap<Felt, UserBalances> =
            serde_json::from_reader(&mut input_reader)?;

        info!("{} balances loaded from file", user_balances.len());

        Ok(user_balances)
    } else {
        let mut user_balances: BTreeMap<Felt, UserBalances> = BTreeMap::new();

        for (ind_user, user) in users.iter().enumerate() {
            let mut collateral_balances: BTreeMap<TokenId, Felt> = BTreeMap::new();
            let mut debt_balances: BTreeMap<TokenId, Felt> = BTreeMap::new();

            let slots = provider
                .batch_requests(
                    ALL_ASSETS
                        .iter()
                        .map(|asset| {
                            ProviderRequestData::GetStorageAt(GetStorageAtRequest {
                                contract_address: asset.z_token_address,
                                key: get_storage_var_address("raw_balances", &[*user]).unwrap(),
                                block_id: BlockId::Number(MARKET_HALT_BLOCK),
                            })
                        })
                        .chain(ALL_ASSETS.iter().map(|asset| {
                            ProviderRequestData::GetStorageAt(GetStorageAtRequest {
                                contract_address: MARKET_ADDRESS,
                                key: get_storage_var_address(
                                    "raw_user_debts",
                                    &[*user, asset.token_address],
                                )
                                .unwrap(),
                                block_id: BlockId::Number(MARKET_HALT_BLOCK),
                            })
                        }))
                        .collect::<Vec<_>>(),
                )
                .await?;

            let mut all_slots = slots.into_iter();

            for balances in [&mut collateral_balances, &mut debt_balances] {
                for (asset, slot) in ALL_ASSETS.iter().zip(&mut all_slots) {
                    let slot = if let ProviderResponseData::GetStorageAt(slot) = slot {
                        slot
                    } else {
                        anyhow::bail!("unexpected response type");
                    };

                    if slot != Felt::ZERO {
                        balances.insert(asset.id, slot);
                    }
                }
            }

            if !collateral_balances.is_empty() || !debt_balances.is_empty() {
                user_balances.insert(
                    *user,
                    UserBalances {
                        collateral: collateral_balances,
                        debt: debt_balances,
                    },
                );
            }

            debug!(
                "User {:#064x} data fetched ({}/{})",
                user,
                ind_user + 1,
                users.len()
            );
        }

        info!(
            "{} users found with non-empty balances",
            user_balances.len()
        );

        let mut output_file = File::create(BALANCES_FILE)?;
        let mut output_writer = BufWriter::new(&mut output_file);

        serde_json::to_writer_pretty(&mut output_writer, &user_balances)?;
        output_writer.write_all(b"\n")?;

        info!("Balance list persisted to {}", BALANCES_FILE);

        Ok(user_balances)
    }
}

async fn fetch_pool_data<P: Provider>(provider: P) -> Result<BTreeMap<TokenId, PoolData>> {
    if std::fs::exists(POOL_DATA_FILE)? {
        debug!("Pool list file found: {}", POOL_DATA_FILE);

        let mut input_file = File::open(POOL_DATA_FILE)?;
        let mut input_reader = BufReader::new(&mut input_file);

        let pools: BTreeMap<TokenId, PoolData> = serde_json::from_reader(&mut input_reader)?;

        info!("{} pools loaded from file", pools.len());

        Ok(pools)
    } else {
        let mut pools: BTreeMap<TokenId, PoolData> = BTreeMap::new();

        for asset in &ALL_ASSETS {
            let mut responses = provider
                .batch_requests(vec![
                    ProviderRequestData::Call(CallRequest {
                        request: FunctionCall {
                            contract_address: MARKET_ADDRESS,
                            entry_point_selector: selector!("get_debt_accumulator"),
                            calldata: vec![asset.token_address],
                        },
                        block_id: BlockId::Number(MARKET_HALT_BLOCK),
                    }),
                    ProviderRequestData::Call(CallRequest {
                        request: FunctionCall {
                            contract_address: MARKET_ADDRESS,
                            entry_point_selector: selector!("get_lending_accumulator"),
                            calldata: vec![asset.token_address],
                        },
                        block_id: BlockId::Number(MARKET_HALT_BLOCK),
                    }),
                    ProviderRequestData::Call(CallRequest {
                        request: FunctionCall {
                            contract_address: asset.token_address,
                            entry_point_selector: selector!("balanceOf"),
                            calldata: vec![MARKET_ADDRESS],
                        },
                        block_id: BlockId::Number(MARKET_HALT_BLOCK),
                    }),
                    ProviderRequestData::Call(CallRequest {
                        request: FunctionCall {
                            contract_address: asset.token_address,
                            entry_point_selector: selector!("decimals"),
                            calldata: vec![],
                        },
                        block_id: BlockId::Number(MARKET_HALT_BLOCK),
                    }),
                    ProviderRequestData::Call(CallRequest {
                        request: FunctionCall {
                            contract_address: ORACLE_ADDRESS,
                            entry_point_selector: selector!("get_price"),
                            calldata: vec![asset.token_address],
                        },
                        block_id: BlockId::Number(MARKET_HALT_BLOCK),
                    }),
                ])
                .await?;

            let price = if let ProviderResponseData::Call(response) = responses.pop().unwrap() {
                response[0]
            } else {
                anyhow::bail!("unexpected response type");
            };

            let decimals = if let ProviderResponseData::Call(response) = responses.pop().unwrap() {
                response[0].try_into()?
            } else {
                anyhow::bail!("unexpected response type");
            };

            let balance = if let ProviderResponseData::Call(response) = responses.pop().unwrap() {
                response[0]
            } else {
                anyhow::bail!("unexpected response type");
            };

            let lending_accumulator =
                if let ProviderResponseData::Call(response) = responses.pop().unwrap() {
                    response[0]
                } else {
                    anyhow::bail!("unexpected response type");
                };

            let debt_accumulator =
                if let ProviderResponseData::Call(response) = responses.pop().unwrap() {
                    response[0]
                } else {
                    anyhow::bail!("unexpected response type");
                };

            let pool_data = PoolData {
                price,
                decimals,
                balance,
                lending_accumulator,
                debt_accumulator,
            };

            pools.insert(asset.id, pool_data);
        }

        info!("{} pools fetched", pools.len());

        let mut output_file = File::create(POOL_DATA_FILE)?;
        let mut output_writer = BufWriter::new(&mut output_file);

        serde_json::to_writer_pretty(&mut output_writer, &pools)?;
        output_writer.write_all(b"\n")?;

        info!("Pool list persisted to {}", POOL_DATA_FILE);

        Ok(pools)
    }
}

fn generate_claims(
    user_balances: &BTreeMap<Felt, UserBalances>,
    pool_data: &BTreeMap<TokenId, PoolData>,
) -> Result<()> {
    debug!(
        "Generating claims for {} users on {} pools",
        user_balances.len(),
        pool_data.len()
    );

    let attacker_set = ATTACKER_ACCOUNTS.into_iter().collect::<BTreeSet<Felt>>();
    let treasury_set = TREASURY_ACCOUNTS.into_iter().collect::<BTreeSet<Felt>>();

    // Calculate user net asset
    let mut user_net_raw_supplies: BTreeMap<Felt, BTreeMap<TokenId, Felt>> = BTreeMap::new();
    for (user, balances) in user_balances {
        let user_collateral_value = balances
            .collateral
            .iter()
            .map(|(token_id, raw_amount)| {
                let pool = pool_data.get(token_id).unwrap();

                ((raw_amount * pool.lending_accumulator)
                    .floor_div(&ACCUMULATOR_SCALE.try_into().unwrap())
                    * pool.price)
                    .floor_div(&Felt::from(10u128.pow(pool.decimals)).try_into().unwrap())
            })
            .fold(Felt::ZERO, |acc, e| acc + e);
        let user_debt_value = balances
            .debt
            .iter()
            .map(|(token_id, raw_amount)| {
                let pool = pool_data.get(token_id).unwrap();

                ((raw_amount * pool.debt_accumulator)
                    .floor_div(&ACCUMULATOR_SCALE.try_into().unwrap())
                    * pool.price)
                    .floor_div(&Felt::from(10u128.pow(pool.decimals)).try_into().unwrap())
            })
            .fold(Felt::ZERO, |acc, e| acc + e);

        // Attacker has no claim
        if attacker_set.contains(user) {
            debug!("Attacker account found: {:#064x}", user);
            continue;
        }

        // Team treasury wiped
        if treasury_set.contains(user) {
            debug!(
                "Treasury account found: {:#064x}; collateral = {} USD; debt = {} USD",
                user,
                felt_to_bigdecimal(user_collateral_value, USD_DECIMALS),
                felt_to_bigdecimal(user_debt_value, USD_DECIMALS),
            );
            continue;
        }

        // Protocol revenue wiped
        if user == &REVENUE_ACCOUNT {
            debug!(
                "Revenue account found: {:#064x}; collateral = {} USD; debt = {} USD",
                user,
                felt_to_bigdecimal(user_collateral_value, USD_DECIMALS),
                felt_to_bigdecimal(user_debt_value, USD_DECIMALS),
            );
            continue;
        }

        // Bankrupt user
        if user_debt_value > user_collateral_value {
            trace!("Bankrupt user found: {:#064x}", user);
            continue;
        }

        // Dust amounts
        if user_debt_value == Felt::ZERO && user_collateral_value == Felt::ZERO {
            continue;
        }

        let debt_portion =
            (user_debt_value * ACCUMULATOR_SCALE).floor_div(&user_collateral_value.try_into()?);

        let adjusted_balances = balances
            .collateral
            .iter()
            .flat_map(|(token_id, original_balance)| {
                let adjusted_amount = (original_balance * (ACCUMULATOR_SCALE - debt_portion))
                    .floor_div(&ACCUMULATOR_SCALE.try_into().unwrap());

                if adjusted_amount != Felt::ZERO {
                    Some((*token_id, adjusted_amount))
                } else {
                    None
                }
            })
            .collect::<BTreeMap<TokenId, Felt>>();

        user_net_raw_supplies.insert(*user, adjusted_balances);
    }

    let mut pool_results = vec![];

    for (token_id, pool) in pool_data {
        let total_raw_claim = user_net_raw_supplies
            .iter()
            .flat_map(|(_, balances)| balances.get(token_id).copied())
            .fold(Felt::ZERO, |acc, e| acc + e);

        let total_claim =
            (total_raw_claim * pool.lending_accumulator).floor_div(&ACCUMULATOR_SCALE.try_into()?);

        let usd_surplus: i128 = if pool.balance >= total_claim {
            ((pool.balance - total_claim) * pool.price)
                .floor_div(&Felt::from(10u128.pow(pool.decimals)).try_into()?)
                .try_into()?
        } else {
            -((total_claim - pool.balance) * pool.price)
                .floor_div(&Felt::from(10u128.pow(pool.decimals)).try_into()?)
                .try_into()?
        };

        let pool_affected = ALL_ASSETS
            .iter()
            .find(|asset| &asset.id == token_id)
            .unwrap()
            .is_affected;

        pool_results.push(PoolResult {
            token_id: *token_id,
            decimals: pool.decimals,
            price: pool.price,
            is_affected: pool_affected,
            balance: pool.balance,
            claim: total_claim,
            usd_surplus,
        });
    }

    info!("Unaffected pools:");

    for pool in pool_results.iter().filter(|pool| !pool.is_affected) {
        info!(
            "{}: balance = {}; claim = {} (surplus = {} USD)",
            pool.token_id,
            felt_to_bigdecimal(pool.balance, pool.decimals),
            felt_to_bigdecimal(pool.claim, pool.decimals),
            BigDecimal::new(pool.usd_surplus.into(), USD_DECIMALS as i64),
        );
    }

    let unaffected_surplus: i128 = pool_results
        .iter()
        .filter_map(|pool| (!pool.is_affected).then_some(pool.usd_surplus))
        .sum();
    info!(
        "Expected aggregated surplus from unaffected pools: {} USD",
        BigDecimal::new(unaffected_surplus.into(), USD_DECIMALS as i64)
    );

    // WSTETHV1 pool is to be fully socialized
    let wstethv1_pool = pool_results
        .iter()
        .find(|pool| pool.token_id == TokenId::WSTETHV1)
        .unwrap();
    info!(
        "Expected surplus from {} {}: {} USD",
        felt_to_bigdecimal(wstethv1_pool.balance, wstethv1_pool.decimals),
        TokenId::WSTETHV1,
        BigDecimal::new(wstethv1_pool.usd_surplus.into(), USD_DECIMALS as i64)
    );

    // TODO: once actual liquidation happens replace this with exact proceeds
    let socialization_budget = unaffected_surplus + wstethv1_pool.usd_surplus;
    info!(
        "Expected surplus socialization budget: {} USD",
        BigDecimal::new(socialization_budget.into(), USD_DECIMALS as i64)
    );
    assert!(socialization_budget > 0);

    // This forms the basis of socialization of unaffected surplus
    let affected_surplus: i128 = pool_results
        .iter()
        .filter_map(|pool| {
            (pool.is_affected && pool.token_id != TokenId::WSTETHV1).then_some(pool.usd_surplus)
        })
        .sum();
    assert!(affected_surplus < 0);

    info!(
        "Aggregated surplus from affected pools: {} USD ({} USD after socialization)",
        BigDecimal::new(affected_surplus.into(), USD_DECIMALS as i64),
        BigDecimal::new(
            (affected_surplus + socialization_budget).into(),
            USD_DECIMALS as i64
        ),
    );

    info!("Expected affected pool recovery:");

    let mut pool_socialization_amounts: BTreeMap<TokenId, Felt> = BTreeMap::new();
    for pool in pool_results
        .iter()
        .filter(|pool| pool.is_affected && pool.token_id != TokenId::WSTETHV1)
    {
        assert!(pool.usd_surplus < 0);

        let pool_socialization: i128 = (Felt::from(pool.usd_surplus.unsigned_abs())
            * Felt::from(socialization_budget.unsigned_abs()))
        .floor_div(&(Felt::from(affected_surplus.unsigned_abs())).try_into()?)
        .try_into()?;

        let surplus_with_socialization = pool.usd_surplus + pool_socialization;
        let socialization_in_token_amount = (Felt::from(pool_socialization)
            * Felt::from(10u128.pow(pool.decimals)))
        .floor_div(&pool.price.try_into()?);

        pool_socialization_amounts.insert(pool.token_id, socialization_in_token_amount);

        info!(
            "{}: balance = {}; claim = {}; surplus = {} USD; surplus w/ socialization: {} USD \
            ({} {}) \
            (recovery: {:.02}% -> {:.02}%)",
            pool.token_id,
            felt_to_bigdecimal(pool.balance, pool.decimals),
            felt_to_bigdecimal(pool.claim, pool.decimals),
            BigDecimal::new(pool.usd_surplus.into(), USD_DECIMALS as i64),
            BigDecimal::new(surplus_with_socialization.into(), USD_DECIMALS as i64),
            felt_to_bigdecimal(socialization_in_token_amount, pool.decimals),
            pool.token_id,
            felt_to_bigdecimal(
                (pool.balance * ACCUMULATOR_SCALE).floor_div(&pool.claim.try_into()?),
                ACCUMULATOR_DECIMALS - 2
            ),
            felt_to_bigdecimal(
                ((pool.balance + socialization_in_token_amount) * ACCUMULATOR_SCALE)
                    .floor_div(&pool.claim.try_into()?),
                ACCUMULATOR_DECIMALS - 2
            ),
        );
    }

    let mut claims: BTreeMap<Felt, Claim> = BTreeMap::new();

    for (user, net_raw_supplies) in user_net_raw_supplies {
        let mut current_user_claim = Claim {
            withdrawable: BTreeMap::new(),
            usd_shortfall: Felt::ZERO,
        };

        for (token_id, net_raw_supply) in net_raw_supplies
            .iter()
            .filter(|(token_id, _)| *token_id != &TokenId::WSTETHV1)
        {
            let asset = ALL_ASSETS
                .iter()
                .find(|asset| asset.id == *token_id)
                .unwrap();
            let pool = pool_data.get(token_id).unwrap();
            let pool_result = pool_results
                .iter()
                .find(|pool| pool.token_id == *token_id)
                .unwrap();

            let scaled_net_supply = (net_raw_supply * pool.lending_accumulator)
                .floor_div(&ACCUMULATOR_SCALE.try_into()?);

            if asset.is_affected {
                let immediately_withdrawable = (scaled_net_supply
                    * (pool.balance + pool_socialization_amounts.get(token_id).unwrap()))
                .floor_div(&pool_result.claim.try_into()?);

                let shortfall_in_amount = scaled_net_supply - immediately_withdrawable;
                let shortfall_in_usd = (shortfall_in_amount * pool.price)
                    .floor_div(&Felt::from(10u128.pow(pool.decimals)).try_into()?);

                if immediately_withdrawable != Felt::ZERO {
                    current_user_claim
                        .withdrawable
                        .insert(*token_id, immediately_withdrawable);
                }

                if shortfall_in_usd != Felt::ZERO {
                    current_user_claim.usd_shortfall += shortfall_in_usd;
                }

                // NOTE: this is only the expected amount due to pending liquidation
                // TODO: ensure the actual socialization budget is updated
            } else {
                // Unaffected pools are guaranteed to be made whole
                current_user_claim
                    .withdrawable
                    .insert(*token_id, scaled_net_supply);
            }
        }

        if !current_user_claim.withdrawable.is_empty()
            || current_user_claim.usd_shortfall != Felt::ZERO
        {
            claims.insert(user, current_user_claim);
        }
    }

    info!("Claims generated for {} users", claims.len());

    // Sanity checks
    for asset in ALL_ASSETS {
        let total_claim = claims
            .iter()
            .flat_map(|(_, claim)| claim.withdrawable.get(&asset.id))
            .fold(Felt::ZERO, |acc, e| acc + e);
        info!(
            "Claim on {}: {} {}",
            asset.id,
            felt_to_bigdecimal(total_claim, pool_data.get(&asset.id).unwrap().decimals),
            asset.id
        );
    }
    let total_claim_usd_shortfall = claims
        .values()
        .map(|claim| claim.usd_shortfall)
        .fold(Felt::ZERO, |acc, e| acc + e);
    info!(
        "Total claim USD shortfall: {} USD",
        felt_to_bigdecimal(total_claim_usd_shortfall, USD_DECIMALS),
    );

    let mut user_claims = claims
        .into_iter()
        .map(|(user, claim)| UserClaim { user, claim })
        .collect::<Vec<_>>();
    user_claims.sort_by(
        |x, y| match x.claim.usd_shortfall.cmp(&y.claim.usd_shortfall) {
            Ordering::Equal => y.user.cmp(&x.user),
            Ordering::Less => Ordering::Greater,
            Ordering::Greater => Ordering::Less,
        },
    );

    let mut output_file = File::create(CLAIMS_FILE)?;
    let mut output_writer = BufWriter::new(&mut output_file);

    serde_json::to_writer_pretty(&mut output_writer, &user_claims)?;
    output_writer.write_all(b"\n")?;

    info!("Claim list persisted to {}", CLAIMS_FILE);

    let mut report_file = File::create(CLAIMS_REPORT_FILE)?;
    let mut report_writer = BufWriter::new(&mut report_file);

    writeln!(report_writer, "user,usd_shortfall")?;
    for claim in user_claims
        .iter()
        .filter(|claim| claim.claim.usd_shortfall > Felt::ZERO)
    {
        writeln!(
            report_writer,
            "{:#064x},{}",
            claim.user,
            felt_to_bigdecimal(claim.claim.usd_shortfall, USD_DECIMALS)
        )?;
    }

    info!("Claim report persisted to {}", CLAIMS_REPORT_FILE);

    Ok(())
}

fn felt_to_bigdecimal<F, D>(felt: F, decimals: D) -> BigDecimal
where
    F: AsRef<Felt>,
    D: Into<i64>,
{
    BigDecimal::new(
        BigInt::from_bytes_be(Sign::Plus, &felt.as_ref().to_bytes_be()),
        decimals.into(),
    )
}
