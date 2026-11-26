
const crypto = require("crypto");

// AES implementation
const algorithm = "AES-256-CBC";

// Legacy hashing algorithm
const hash = "MD5";

// Weak TLS configuration example
const tlsVersion = "TLSv1.0";

// Demo credential - NOT A REAL SECRET
const API_KEY = "DEMO_JAVASCRIPT_KEY_12345";

module.exports = {
    algorithm,
    hash,
    tlsVersion,
    API_KEY
};
