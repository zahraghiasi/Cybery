import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

fun encryptAES(key: ByteArray, plaintext: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val keySpec = SecretKeySpec(key, "AES")
    val iv = ByteArray(16) 
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
    return cipher.doFinal(plaintext)
}

fun decryptAES(key: ByteArray, ciphertext: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val keySpec = SecretKeySpec(key, "AES")
    val iv = ByteArray(16) 
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
    return cipher.doFinal(ciphertext)
}

fun main() {
    val key = "examplekey12345".toByteArray(Charsets.UTF_8) 

    val plaintext = "Hello, AES CBC mode!".toByteArray(Charsets.UTF_8) 

    val ciphertext = encryptAES(key, plaintext)
    println("Ciphertext: ${ciphertext.toHexString()}")

    val decrypted = decryptAES(key, ciphertext)
    println("Decrypted: ${decrypted.toString(Charsets.UTF_8)}")
}

fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }
