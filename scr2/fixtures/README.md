# Benign local proof screen

`proof-screen.dex` is the same 5,120-byte source-built fixture used for Family3.
SHA-256: `8de5fb444a932ad2eb5af51fb1082f4cf6d293441808f37ab84e546e936017d0`.

Entry: `com.apkdefense.fixture.webview.ResponseEntry.run(android.app.Activity)`.
The included `source/ResponseEntry.java` displays local HTML headed
“APK Defense: DEX executed” and a button whose label changes to
“DEX button handler executed”. It uses the supplied Activity and makes no network
request. The app hosting it can still perform its own network activity.

The analyzer checks the exact fixture hash and encodes its bytes according to the
recovered DEX field encoding. It emits `response.proof.json` automatically for
compatible contracts. Generating that file does not prove execution; capture the
screen, button behavior and runtime evidence during a separate authorized test.

Lab build source: `test-fixtures/webview-google/`; build helper:
`scripts/build_response_dex_fixture.sh`. Build tool changes can produce different
bytes; replacement DEX files are deliberately rejected until explicitly reviewed.
