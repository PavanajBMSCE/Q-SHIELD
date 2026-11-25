const crypto = require("crypto");

// Updated cryptographic configuration profile.
const algorithm = "AES-256-GCM";
const hash = "SHA-256";
const tlsVersion = "TLSv1.3";

// Configure API_KEY in the deployment environment; never commit its value.
const API_KEY = process.env.API_KEY;

module.exports = {
    algorithm,
    hash,
    tlsVersion,
    API_KEY
};
