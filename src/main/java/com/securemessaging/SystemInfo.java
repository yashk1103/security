package com.securemessaging;

/**
 * System information about the crypto library
 */
public class SystemInfo {
    private final String version;
    private final String algorithm;
    private final boolean supports512Bit;
    private final boolean supports1488Bit;
    private final String securityFeatures;
    
    public SystemInfo(String version, String algorithm, boolean supports512Bit, 
                     boolean supports1488Bit, String securityFeatures) {
        this.version = version;
        this.algorithm = algorithm;
        this.supports512Bit = supports512Bit;
        this.supports1488Bit = supports1488Bit;
        this.securityFeatures = securityFeatures;
    }
    
    public String getVersion() { return version; }
    public String getAlgorithm() { return algorithm; }
    public boolean supports512Bit() { return supports512Bit; }
    public boolean supports1488Bit() { return supports1488Bit; }
    public String getSecurityFeatures() { return securityFeatures; }
    
    @Override
    public String toString() {
        return String.format("SystemInfo{version='%s', algorithm='%s', 512-bit=%s, 1488-bit=%s, features='%s'}", 
                           version, algorithm, supports512Bit, supports1488Bit, securityFeatures);
    }
}
