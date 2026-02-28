/*
   YARA Rules - Cryptominer Detection
   Compatible with: YARA v4.x
   Author: KoraAV Project Default
   Description: Detects cryptocurrency miners
   Last Updated: 2025-02-23
*/

rule Generic_Cryptominer {
    meta:
        description = "Generic cryptocurrency miner indicators"
        severity = "medium"
        confidence = "medium"
        category = "cryptominer"
        
    strings:
        // Mining pools
        $pool1 = "stratum+tcp://" nocase
        $pool2 = "stratum+ssl://" nocase
        $pool3 = ".pool." nocase
        $pool4 = "mining" nocase
        
        // Cryptocurrencies
        $crypto1 = "monero" nocase
        $crypto2 = "ethereum" nocase
        $crypto3 = "bitcoin" nocase
        $crypto4 = "XMR" nocase
        $crypto5 = "ETH" nocase
        
        // Mining terms
        $mining1 = "hashrate" nocase
        $mining2 = "difficulty" nocase
        $mining3 = "nonce" nocase
        $mining4 = "accepted" nocase
        $mining5 = "rejected" nocase
        
    condition:
        (1 of ($pool*) and 1 of ($crypto*)) or
        (2 of ($pool*) and 2 of ($mining*)) or
        (3 of ($mining*) and 1 of ($crypto*))
}

rule XMRig_Miner {
    meta:
        description = "Detects XMRig Monero miner"
        severity = "medium"
        confidence = "high"
        category = "cryptominer"
        family = "XMRig"
        
    strings:
        $str1 = "XMRig" nocase
        $str2 = "xmrig" nocase
        $str3 = "donate-level" nocase
        $str4 = "algo" nocase
        $str5 = "randomx" nocase
        $str6 = "cryptonight" nocase
        
    condition:
        2 of them
}

rule Cgminer {
    meta:
        description = "Detects cgminer cryptocurrency miner"
        severity = "medium"
        confidence = "high"
        category = "cryptominer"
        family = "cgminer"
        
    strings:
        $str1 = "cgminer" nocase
        $str2 = "--api-listen" nocase
        $str3 = "--pools" nocase
        $str4 = "--gpu-platform" nocase
        
    condition:
        2 of them
}

rule Coinhive_WebMiner {
    meta:
        description = "Detects Coinhive web miner"
        severity = "medium"
        confidence = "high"
        category = "cryptominer"
        family = "Coinhive"
        
    strings:
        $str1 = "coinhive" nocase
        $str2 = "CoinHive.Anonymous" nocase
        $str3 = "authedmine.com" nocase
        $str4 = "coin-hive.com" nocase
        
    condition:
        1 of them
}

rule NiceHash_Miner {
    meta:
        description = "Detects NiceHash miner"
        severity = "low"
        confidence = "high"
        category = "cryptominer"
        family = "NiceHash"
        note = "NiceHash is legitimate software but may be abused"
        
    strings:
        $str1 = "NiceHash" nocase
        $str2 = "nicehash.com" nocase
        $str3 = "miner_" nocase
        
    condition:
        2 of them
}

rule Generic_GPU_Miner {
    meta:
        description = "Generic GPU mining detection"
        severity = "medium"
        confidence = "low"
        category = "cryptominer"
        
    strings:
        $gpu1 = "OpenCL" nocase
        $gpu2 = "CUDA" nocase
        $gpu3 = "GPU" nocase
        
        $mining1 = "hash" nocase
        $mining2 = "mining" nocase
        $mining3 = "miner" nocase
        
    condition:
        (1 of ($gpu*) and 2 of ($mining*))
}

