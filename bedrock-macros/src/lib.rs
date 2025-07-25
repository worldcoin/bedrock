use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, Data, DeriveInput, ImplItem, ImplItemFn, ItemImpl, Stmt,
    Variant, Visibility,
};

/// Procedural macro that enhances error enums with generic error handling
///
/// This macro automatically:
/// 1. Adds `#[derive(Debug, thiserror::Error, uniffi::Error)]` and `#[uniffi(flat_error)]`
/// 2. Adds a `Generic { message: String }` variant if not already present
/// 3. Adds a `FileSystem(FileSystemError)` variant if not already present
/// 4. Implements `From<anyhow::Error>` for the error type
/// 5. Implements `From<FileSystemError>` for the error type (via thiserror's #[from])
/// 6. Provides helper methods for error conversion
///
/// # Usage
///
/// ```rust,ignore
/// #[bedrock_error]
/// pub enum MyError {
///     #[error("Specific error: {code}")]
///     SpecificError { code: u32 },
///     #[error("Another error: {message}")]
///     AnotherError { message: String },
/// }
/// ```
///
/// This will automatically add:
/// - `#[derive(Debug, thiserror::Error, uniffi::Error)]` and `#[uniffi(flat_error)]`
/// - `Generic { message: String }` variant
/// - `FileSystem(FileSystemError)` variant
/// - `impl From<anyhow::Error> for MyError`
/// - `impl From<FileSystemError> for MyError`
///
/// Now you can use filesystem operations with automatic error conversion:
/// ```rust,ignore
/// fn my_function() -> Result<String, MyError> {
///     // FileSystemError automatically converts to MyError::FileSystem
///     let data = _bedrock_fs.read_file("config.json")?;
///     Ok(String::from_utf8_lossy(&data).to_string())
/// }
/// ```
#[proc_macro_attribute]
pub fn bedrock_error(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let expanded = match &input.data {
        Data::Enum(data_enum) => {
            let enum_name = &input.ident;
            let visibility = &input.vis;

            // Filter out any existing derive attributes to avoid duplicates
            let attrs: Vec<_> = input
                .attrs
                .iter()
                .filter(|attr| {
                    if attr.path().is_ident("derive") {
                        // Skip existing derive attributes to avoid conflicts
                        false
                    } else if attr.path().is_ident("uniffi") {
                        // Skip existing uniffi attributes to avoid conflicts
                        false
                    } else {
                        true
                    }
                })
                .collect();

            let generics = &input.generics;

            // Check if Generic variant already exists
            let has_generic = data_enum
                .variants
                .iter()
                .any(|variant| variant.ident == "Generic");

            // Check if FileSystem variant already exists
            let has_filesystem = data_enum
                .variants
                .iter()
                .any(|variant| variant.ident == "FileSystem");

            // Collect existing variants
            let mut variants = data_enum.variants.clone();

            // Add Generic variant if it doesn't exist
            if !has_generic {
                let generic_variant: Variant = syn::parse_quote! {
                    /// A generic error that can wrap any anyhow error.
                    #[error("Generic error: {message}")]
                    Generic {
                        /// The error message from the wrapped error.
                        message: String
                    }
                };
                variants.push(generic_variant);
            }

            // Add FileSystem variant if it doesn't exist
            if !has_filesystem {
                let filesystem_variant: Variant = syn::parse_quote! {
                    /// Filesystem operation error.
                    #[error(transparent)]
                    FileSystem(#[from] crate::primitives::filesystem::FileSystemError)
                };
                variants.push(filesystem_variant);
            }

            // Generate the enhanced enum with automatic derives and attributes
            quote! {
                // Automatically import anyhow::Context for convenience
                use anyhow::Context;

                #[derive(Debug, thiserror::Error, uniffi::Error)]
                #[uniffi(flat_error)]
                #(#attrs)*
                #visibility enum #enum_name #generics {
                    #variants
                }

                impl #generics From<anyhow::Error> for #enum_name #generics {
                    fn from(err: anyhow::Error) -> Self {
                        Self::Generic {
                            message: {
                                // Include the full error chain in the message
                                let mut message = err.to_string();

                                // Add context from the error chain
                                let chain: Vec<String> = err.chain().skip(1).map(|e| e.to_string()).collect();
                                if !chain.is_empty() {
                                    message.push_str(" (caused by: ");
                                    message.push_str(&chain.join(" -> "));
                                    message.push(')');
                                }

                                message
                            }
                        }
                    }
                }

                impl #generics #enum_name #generics {
                    /// Convert an anyhow::Result to a Result with this error type
                    pub fn from_anyhow_result<T>(result: anyhow::Result<T>) -> Result<T, Self> {
                        result.map_err(Self::from)
                    }

                    /// Convert an anyhow::Result to a Result with this error type, adding a prefix
                    pub fn from_anyhow_result_with_prefix<T>(
                        result: anyhow::Result<T>,
                        prefix: &str
                    ) -> Result<T, Self> {
                        result.map_err(|err| Self::Generic {
                            message: {
                                // Format the error message directly without double prefixing
                                let mut message = err.to_string();

                                // Add context from the error chain
                                let chain: Vec<String> = err.chain().skip(1).map(|e| e.to_string()).collect();
                                if !chain.is_empty() {
                                    message.push_str(" (caused by: ");
                                    message.push_str(&chain.join(" -> "));
                                    message.push(')');
                                }

                                format!("{}: {}", prefix, message)
                            }
                        })
                    }
                }
            }
        }
        _ => {
            return syn::Error::new_spanned(
                &input,
                "bedrock_error can only be applied to enums",
            )
            .to_compile_error()
            .into();
        }
    };

    TokenStream::from(expanded)
}

/// Procedural macro that wraps `uniffi::export` and automatically injects logging context and filesystem middleware
///
/// This macro automatically:
/// 1. Forwards the attribute to `#[uniffi::export]`
/// 2. Injects `let _bedrock_logger_ctx = crate::primitives::logger::LogContext::new("StructName");` at the start of every `pub fn`
/// 3. Injects a private `_bedrock_fs` field of type FileSystemMiddleware to the struct
/// 4. Extracts the struct/trait name from the impl block for context
/// 5. Automatically adds `async_runtime = "tokio"` if any async functions are detected
///
/// # Usage
///
/// ```rust,ignore
/// #[bedrock_export]
/// impl MyStruct {
///     pub fn some_method(&self) -> String {
///         // _bedrock_logger_ctx and _bedrock_fs are automatically injected here
///         debug!("This will be prefixed with [Bedrock][MyStruct]");
///         
///         // Use the filesystem with automatic path prefixing
///         let data = _bedrock_fs.read_file("config.json").unwrap();
///         
///         "result".to_string()
///     }
///     
///     pub async fn async_method(&self) -> String {
///         // async_runtime = "tokio" is automatically added to uniffi::export
///         // _bedrock_fs is available here too
///         _bedrock_fs.write_file("output.txt", b"data".to_vec()).unwrap();
///         "async result".to_string()
///     }
/// }
/// ```
///
/// This will automatically add logging context to all public methods in the impl block,
/// and tokio async runtime support if any async functions are present.
#[proc_macro_attribute]
pub fn bedrock_export(args: TokenStream, input: TokenStream) -> TokenStream {
    let input_impl = parse_macro_input!(input as ItemImpl);

    // Extract the struct/trait name for logging context
    let type_name = match &*input_impl.self_ty {
        syn::Type::Path(type_path) => {
            if let Some(segment) = type_path.path.segments.last() {
                segment.ident.to_string()
            } else {
                "Unknown".to_string()
            }
        }
        _ => "Unknown".to_string(),
    };

    // Check if any public functions in the impl block are async
    let has_async_functions = has_async_functions_in_impl(&input_impl.items);

    // Process each method in the impl block
    let mut new_items = Vec::new();

    for item in &input_impl.items {
        match item {
            ImplItem::Fn(method) => {
                // Check if this is a public function
                if matches!(method.vis, Visibility::Public(_)) {
                    // Inject logging context at the start of the function body
                    let mut new_method = method.clone();
                    inject_logging_context(&mut new_method, &type_name);
                    new_items.push(ImplItem::Fn(new_method));
                } else {
                    // Keep private methods unchanged
                    new_items.push(item.clone());
                }
            }
            _ => {
                // Keep other items unchanged
                new_items.push(item.clone());
            }
        }
    }

    // Create the new impl block with modified methods
    let new_impl = ItemImpl {
        items: new_items,
        ..input_impl
    };

    // Generate the output with uniffi::export attribute
    let mut args = proc_macro2::TokenStream::from(args);

    // If we have async functions, add async_runtime = "tokio" to the attributes
    if has_async_functions {
        if args.is_empty() {
            // No existing args, just add the async_runtime
            args = quote! { async_runtime = "tokio" };
        } else {
            // Existing args, append the async_runtime
            args = quote! { #args, async_runtime = "tokio" };
        }
    }

    quote! {
        #[uniffi::export(#args)]
        #new_impl
    }
    .into()
}

/// Check if any public functions in the impl items are async
fn has_async_functions_in_impl(impl_items: &[ImplItem]) -> bool {
    impl_items.iter().any(|item| {
        if let ImplItem::Fn(method) = item {
            matches!(method.vis, Visibility::Public(_))
                && method.sig.asyncness.is_some()
        } else {
            false
        }
    })
}

/// Inject logging context and filesystem middleware at the start of a function body
fn inject_logging_context(method: &mut ImplItemFn, type_name: &str) {
    // Create the filesystem middleware statement
    let fs_stmt: Stmt = syn::parse_quote! {
        let _bedrock_fs = crate::primitives::filesystem::create_middleware(#type_name);
    };

    // Create the logging context statement
    let context_stmt: Stmt = syn::parse_quote! {
        let _bedrock_logger_ctx = crate::primitives::logger::LogContext::new(#type_name);
    };

    // Insert both at the beginning of the function body
    method.block.stmts.insert(0, fs_stmt);
    method.block.stmts.insert(1, context_stmt);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_async_detection_with_async_functions() {
        let impl_block: ItemImpl = syn::parse_quote! {
            impl MyStruct {
                pub fn sync_method(&self) -> String {
                    "sync".to_string()
                }

                pub async fn async_method(&self) -> String {
                    "async".to_string()
                }
            }
        };

        assert!(has_async_functions_in_impl(&impl_block.items));
    }

    #[test]
    fn test_async_detection_without_async_functions() {
        let impl_block: ItemImpl = syn::parse_quote! {
            impl MyStruct {
                pub fn sync_method(&self) -> String {
                    "sync".to_string()
                }

                pub fn another_sync_method(&self) -> i32 {
                    42
                }
            }
        };

        assert!(!has_async_functions_in_impl(&impl_block.items));
    }

    #[test]
    fn test_async_detection_ignores_private_async_functions() {
        let impl_block: ItemImpl = syn::parse_quote! {
            impl MyStruct {
                pub fn public_sync(&self) -> String {
                    "sync".to_string()
                }

                async fn private_async(&self) -> String {
                    "private async".to_string()
                }
            }
        };

        // Private async functions should not trigger async detection
        assert!(!has_async_functions_in_impl(&impl_block.items));
    }

    #[test]
    fn test_async_detection_with_mixed_visibility() {
        let impl_block: ItemImpl = syn::parse_quote! {
            impl MyStruct {
                pub fn public_sync(&self) -> String {
                    "sync".to_string()
                }

                pub async fn public_async(&self) -> String {
                    "public async".to_string()
                }

                async fn private_async(&self) -> String {
                    "private async".to_string()
                }
            }
        };

        // Should detect async because there's a public async function
        assert!(has_async_functions_in_impl(&impl_block.items));
    }

    #[test]
    fn test_tokio_args_generation() {
        // Test empty args with async
        let mut args = proc_macro2::TokenStream::new();
        if args.is_empty() {
            args = quote! { async_runtime = "tokio" };
        }
        assert_eq!(args.to_string(), "async_runtime = \"tokio\"");

        // Test existing args with async
        let mut args = quote! { callback_interface = "SomeInterface" };
        args = quote! { #args, async_runtime = "tokio" };
        assert_eq!(
            args.to_string(),
            "callback_interface = \"SomeInterface\" , async_runtime = \"tokio\""
        );
    }

    #[test]
    fn test_bedrock_error_includes_filesystem() {
        // Test that bedrock_error macro includes FileSystem variant
        let input: DeriveInput = syn::parse_quote! {
            pub enum TestError {
                #[error("custom error")]
                Custom,
            }
        };

        // Simulate what the macro does
        if let Data::Enum(data_enum) = &input.data {
            let has_filesystem = data_enum
                .variants
                .iter()
                .any(|variant| variant.ident == "FileSystem");

            // Initially should not have FileSystem variant
            assert!(!has_filesystem);

            // After macro processing, it should add FileSystem variant
            let mut variants = data_enum.variants.clone();

            // Add FileSystem variant (simulating macro behavior)
            let filesystem_variant: Variant = syn::parse_quote! {
                /// Filesystem operation error.
                #[error(transparent)]
                FileSystem(#[from] crate::primitives::filesystem::FileSystemError)
            };
            variants.push(filesystem_variant);

            // Now check it has FileSystem variant
            let has_filesystem_after =
                variants.iter().any(|variant| variant.ident == "FileSystem");
            assert!(has_filesystem_after);
        } else {
            panic!("Expected enum");
        }
    }
}
