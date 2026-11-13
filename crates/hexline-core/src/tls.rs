//! Hands the platform verifier the app's context, so `wss` connections are
//! checked by Android's own trust manager, user CAs included.

use jni::objects::{JClass, JObject};
use jni::EnvUnowned;

/// `org.foggyden.hexline.core.Tls.init(context)`, called once at startup
/// before any connection.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_foggyden_hexline_core_Tls_init<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    context: JObject<'caller>,
) {
    unowned_env
        .with_env(|env| rustls_platform_verifier::android::init_with_env(env, context))
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}
