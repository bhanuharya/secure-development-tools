// Annotated tests for kotlin/security.yaml.
fun tainted(input: String) {
    // ruleid: scp.kotlin.injection.command
    Runtime.getRuntime().exec(input)
}

fun safe(input: String) {
    // ok: scp.kotlin.injection.command
    ProcessBuilder("echo", input).start()
}
