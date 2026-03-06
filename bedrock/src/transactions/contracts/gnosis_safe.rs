//! Gnosis Safe (Safe Smart Account) contract interface.
//!
//! Provides read helpers for querying Safe contract state and transaction types
//! for `enableModule` and singleton upgrade operations.

use alloy::{
    primitives::{Address, Bytes, FixedBytes, U256},
    sol,
    sol_types::SolCall,
};

use alloy::primitives::address;

use crate::primitives::{Network, PrimitiveError};

// ---------------------------------------------------------------------------
// Safe v1.4.1 addresses
// ---------------------------------------------------------------------------

/// Safe v1.4.1 L2 singleton address (multichain deployment).
pub const SAFE_V141_L2_SINGLETON: Address =
    address!("0x29fcB43b46531BcA003ddC8FCB67FFE91900C762");

/// Safe v1.4.1 proxy factory address (multichain deployment).
pub const SAFE_V141_PROXY_FACTORY: Address =
    address!("0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67");

/// Safe v1.4.1 helper/batch contract address.
pub const SAFE_V141_HELPER_BATCH: Address =
    address!("0x866087c23a7eE1fD5498ef84D59aF742f3d4b322");

/// Safe v1.4.1 module setup contract address.
pub const SAFE_V141_MODULE_SETUP: Address =
    address!("0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47");

// ---------------------------------------------------------------------------
// Safe v1.3.0 addresses
// ---------------------------------------------------------------------------

/// Safe v1.3.0 L1 singleton address (multichain deployment).
pub const SAFE_V130_L1_SINGLETON: Address =
    address!("0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552");

/// Safe v1.3.0 L2 singleton address (multichain deployment).
pub const SAFE_V130_L2_SINGLETON: Address =
    address!("0x3E5c63644E683549055b9Be8653de26E0B4CD36E");

/// Safe v1.3.0 proxy factory address (multichain deployment).
pub const SAFE_V130_PROXY_FACTORY: Address =
    address!("0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2");

/// Safe v1.3.0 helper/batch contract address.
pub const SAFE_V130_HELPER_BATCH: Address =
    address!("0x8d98006269238CAEd033b2d94661B29312AD09b7");

/// The Safe version string for v1.3.0.
pub const SAFE_VERSION_130: &str = "1.3.0";

// ---------------------------------------------------------------------------
// Shared / module addresses
// ---------------------------------------------------------------------------

/// The Safe4337Module address that must be enabled on the wallet.
///
/// Multichain address for the v0.3.0 `Safe4337Module`.
/// Reference: <https://github.com/safe-global/safe-modules/blob/4337/v0.3.0/modules/4337/contracts/Safe4337Module.sol>
pub const SAFE_4337_MODULE: Address = address!("0x75cf11467937ce3f2f357ce24ffc3dbf8fd5c226");

/// WorldChain migration contract for upgrading the Safe singleton from v1.3.0 to v1.4.1.
pub const WC_MIGRATION_WALLET_UPGRADE: Address =
    address!("0x526643F69b81B008F46d95CD5ced5eC0edFFDaC6");

/// Storage slot for the Safe fallback handler.
///
/// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/base/FallbackManager.sol>
pub const SAFE_FALLBACK_HANDLER_SLOT: U256 = U256::from_be_bytes(
    FixedBytes::new(hex_literal::hex!(
        "6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5"
    ))
    .0,
);
use crate::smart_account::{
    ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
    TransactionTypeId, UserOperation,
};
use crate::transactions::{RpcClient, RpcError};

sol! {
    /// Safe smart-account interface.
    ///
    /// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/Safe.sol>
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    interface ISafe {
        function setup(
            address[] calldata _owners,
            uint256 _threshold,
            address to,
            bytes calldata data,
            address fallbackHandler,
            address paymentToken,
            uint256 payment,
            address payable paymentReceiver
        ) external;

        function isModuleEnabled(address module) external view returns (bool);
        function enableModule(address module) external;
        function enableModules(address[] memory modules) external;
        function VERSION() external view returns (string);

        /// EIP-1271 validation
        function isValidSignature(bytes32 dataHash, bytes memory signature) external view returns (bytes4);

        /// Execute Safe transaction
        function execTransaction(
            address to,
            uint256 value,
            bytes calldata data,
            uint8 operation,
            uint256 safeTxGas,
            uint256 baseGas,
            uint256 gasPrice,
            address gasToken,
            address payable refundReceiver,
            bytes memory signatures
        ) external payable returns (bool success);
    }

    /// Safe proxy factory interface.
    ///
    /// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/proxies/SafeProxyFactory.sol>
    #[sol(rpc)]
    interface ISafeProxyFactory {
        event ProxyCreation(address indexed proxy, address singleton);

        function createProxyWithNonce(
            address _singleton,
            bytes memory initializer,
            uint256 saltNonce
        ) external returns (address proxy);
    }
}

// ---------------------------------------------------------------------------
// GnosisSafe — read helpers
// ---------------------------------------------------------------------------

/// Helpers for querying Safe contract state.
pub struct GnosisSafe {
    /// The Safe wallet address to query against.
    safe_address: Address,
}

impl GnosisSafe {
    /// Creates a new `GnosisSafe` instance for the given wallet address.
    #[must_use]
    pub fn new(safe_address: Address) -> Self {
        Self { safe_address }
    }

    /// Returns the Safe wallet address.
    #[must_use]
    pub fn safe_address(&self) -> Address {
        self.safe_address
    }

    /// Checks whether a module is enabled on this Safe contract.
    ///
    /// # Returns
    /// `true` if the module is enabled, `false` otherwise.
    ///
    /// # Errors
    /// Returns an `RpcError` if the RPC call fails or the response is invalid.
    pub async fn is_module_enabled(
        &self,
        rpc_client: &RpcClient,
        module: Address,
    ) -> Result<bool, RpcError> {
        let call_data = ISafe::isModuleEnabledCall { module }.abi_encode();

        let result = rpc_client
            .eth_call(Network::WorldChain, self.safe_address, call_data.into())
            .await?;

        if result.len() < 32 {
            return Err(RpcError::InvalidResponse {
                error_message: format!(
                    "Invalid isModuleEnabled response: expected 32 bytes, got {}",
                    result.len()
                ),
            });
        }

        Ok(result[31] == 1)
    }

    /// Fetches the fallback handler address from the Safe contract's storage.
    ///
    /// Reads the `SAFE_FALLBACK_HANDLER_SLOT` directly via `eth_getStorageAt`.
    ///
    /// # Errors
    /// Returns an `RpcError` if the RPC call fails.
    pub async fn fetch_fallback_handler(
        &self,
        rpc_client: &RpcClient,
    ) -> Result<Address, RpcError> {
        let slot_value = rpc_client
            .eth_get_storage_at(
                Network::WorldChain,
                self.safe_address,
                SAFE_FALLBACK_HANDLER_SLOT,
            )
            .await?;

        // The address is stored in the lower 20 bytes of the 32-byte slot
        Ok(Address::from_slice(&slot_value[12..]))
    }

    /// Fetches the version string from the Safe contract.
    ///
    /// Calls the `VERSION()` getter on the Safe implementation contract.
    /// For example, returns `"1.3.0"` or `"1.4.1"`.
    ///
    /// # Errors
    /// Returns an `RpcError` if the RPC call fails or the response cannot be decoded.
    pub async fn fetch_version(
        &self,
        rpc_client: &RpcClient,
    ) -> Result<String, RpcError> {
        let call_data = ISafe::VERSIONCall {}.abi_encode();

        let result = rpc_client
            .eth_call(Network::WorldChain, self.safe_address, call_data.into())
            .await?;

        let decoded = ISafe::VERSIONCall::abi_decode_returns(&result)
            .map_err(|e| RpcError::InvalidResponse {
                error_message: format!("Failed to decode VERSION response: {e}"),
            })?;

        Ok(decoded)
    }
}

// ---------------------------------------------------------------------------
// SafeEnableModule — Is4337Encodable for enableModule calls
// ---------------------------------------------------------------------------

/// Represents a Safe `enableModule` call.
///
/// The Safe contract calls itself to enable a module, so `safe_address` is
/// both the sender and the target of the inner `executeUserOp` call.
pub struct SafeEnableModule {
    /// The Safe contract address (target of the `enableModule` call).
    safe_address: Address,
    /// The ABI-encoded calldata for `enableModule(module)`.
    call_data: Vec<u8>,
}

impl SafeEnableModule {
    /// Creates a new `enableModule` operation.
    ///
    /// # Arguments
    /// * `safe_address` - The Safe wallet address (target of the call).
    /// * `module` - The module address to enable.
    #[must_use]
    pub fn new(safe_address: Address, module: Address) -> Self {
        let call_data = ISafe::enableModuleCall { module }.abi_encode();
        Self {
            safe_address,
            call_data,
        }
    }
}

impl Is4337Encodable for SafeEnableModule {
    type MetadataArg = ();

    fn as_execute_user_op_call_data(&self) -> Bytes {
        ISafe4337Module::executeUserOpCall {
            to: self.safe_address,
            value: U256::ZERO,
            data: self.call_data.clone().into(),
            operation: SafeOperation::Call as u8,
        }
        .abi_encode()
        .into()
    }

    fn as_preflight_user_operation(
        &self,
        wallet_address: Address,
        _metadata: Option<Self::MetadataArg>,
    ) -> Result<UserOperation, PrimitiveError> {
        let call_data = self.as_execute_user_op_call_data();

        let key = NonceKeyV1::new(
            TransactionTypeId::SafeEnable4337Module,
            InstructionFlag::Default,
            [0u8; 10],
        );
        let nonce = key.encode_with_sequence(0);

        Ok(UserOperation::new_with_defaults(
            wallet_address,
            nonce,
            call_data,
        ))
    }
}

// ---------------------------------------------------------------------------
// SafeWalletVersionUpgrade — Is4337Encodable for singleton upgrade via delegatecall
// ---------------------------------------------------------------------------

/// Represents a Safe singleton upgrade via `delegatecall` to the
/// `WC_MIGRATION_WALLET_UPGRADE` contract.
///
/// The migration contract's function selector `0x68cb3d94` handles upgrading
/// the Safe proxy's singleton from v1.3.0 to v1.4.1 and registers the 4337 module as the fallback handler.
pub struct SafeWalletVersionUpgrade;

impl Is4337Encodable for SafeWalletVersionUpgrade {
    type MetadataArg = ();

    fn as_execute_user_op_call_data(&self) -> Bytes {
        ISafe4337Module::executeUserOpCall {
            to: WC_MIGRATION_WALLET_UPGRADE,
            value: U256::ZERO,
            // Function selector for the migration contract's upgrade function
            data: Bytes::from_static(&[0x68, 0xcb, 0x3d, 0x94]),
            operation: SafeOperation::DelegateCall as u8,
        }
        .abi_encode()
        .into()
    }

    fn as_preflight_user_operation(
        &self,
        wallet_address: Address,
        _metadata: Option<Self::MetadataArg>,
    ) -> Result<UserOperation, PrimitiveError> {
        let call_data = self.as_execute_user_op_call_data();

        let key = NonceKeyV1::new(
            TransactionTypeId::SafeWalletVersionUpgrade,
            InstructionFlag::Default,
            [0u8; 10],
        );
        let nonce = key.encode_with_sequence(0);

        Ok(UserOperation::new_with_defaults(
            wallet_address,
            nonce,
            call_data,
        ))
    }
}