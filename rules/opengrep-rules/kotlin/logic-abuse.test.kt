import java.security.SecureRandom
import kotlin.random.Random
import javax.servlet.http.HttpServletRequest
import org.springframework.beans.BeanUtils
import org.springframework.web.bind.annotation.RequestHeader

// Annotated tests for kotlin/logic-abuse.yaml.
class LogicAbuseTest {

    fun otpUnsafe(): Int {
        // ruleid: scp.kotlin.logic.weak-prng-otp-or-token
        val otpCode = Random.nextInt(100000, 999999)
        return otpCode
    }

    fun otpSafe(): Int {
        val sr = SecureRandom()
        // ok: scp.kotlin.logic.weak-prng-otp-or-token
        val otpCode = sr.nextInt(999999)
        // ok: scp.kotlin.logic.weak-prng-otp-or-token
        val retryJitter = Random.nextInt(50, 200)
        return otpCode + retryJitter
    }

    fun readHeaders(
        req: HttpServletRequest,
        // ruleid: scp.kotlin.logic.trust-spoofable-identity-header
        @RequestHeader("X-User-Id") uid: String
    ): String {
        // ruleid: scp.kotlin.logic.trust-spoofable-identity-header
        val role = req.getHeader("X-Role")
        // ok: scp.kotlin.logic.trust-spoofable-identity-header
        val trace = req.getHeader("X-Request-Id")
        return uid + role + trace
    }

    fun copyProps(requestDto: Any, user: Any, existing: Any, target: Any) {
        // ruleid: scp.kotlin.logic.mass-assignment-beanutils
        BeanUtils.copyProperties(requestDto, user)
        // ok: scp.kotlin.logic.mass-assignment-beanutils
        BeanUtils.copyProperties(requestDto, user, "role", "activated")
        // ok: scp.kotlin.logic.mass-assignment-beanutils
        BeanUtils.copyProperties(existing, target)
    }
}
