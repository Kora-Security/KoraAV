/*
   YARA Rules for Cryptocurrency Miner Detection
   Based on real-world cryptominers targeting Linux (2024-2026)
   
   Families covered:
   - XMRig (Monero miner)
   - z0Miner
   - Norman Miner
   - TeamTNT miners
   - Kinsing
   - H2Miner
*/

rule Linux_Miner_XMRig
{
    meta:
        description = "Detects XMRig cryptocurrency miner"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        reference = "Most common Monero miner"
        
    strings:
        // Binary strings
        $xmrig1 = "xmrig" nocase
        $xmrig2 = "XMRig" nocase
        $xmrig3 = "xmr-stak" nocase
        
        // Pool addresses
        $pool1 = "pool.minexmr.com"
        $pool2 = "pool.supportxmr.com"
        $pool3 = "xmr.pool.minergate.com"
        $pool4 = /pool\.[a-z0-9\-]+\.(com|net|org):[0-9]{4,5}/
        
        // Config strings
        $cfg1 = "\"algo\": \"rx/0\""
        $cfg2 = "\"coin\": \"monero\""
        $cfg3 = "\"donate-level\":"
        $cfg4 = "\"randomx\":"
        
        // Wallet patterns
        $wallet = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/  // Monero address
        
        // Mining parameters
        $param1 = "--cpu-priority"
        $param2 = "--threads"
        $param3 = "--randomx-mode"
        $param4 = "-o pool"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            2 of ($xmrig*) or
            (any of ($pool*) and any of ($cfg*)) or
            ($wallet and 2 of ($param*)) or
            (any of ($cfg*) and 2 of ($param*))
        )
}

rule Linux_Miner_z0Miner
{
    meta:
        description = "Detects z0Miner cryptocurrency miner worm"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "Self-propagating miner with worm capabilities"
        
    strings:
        $name = "z0Miner" nocase
        
        // Persistence
        $cron1 = "* * * * * root"
        $cron2 = "/tmp/.X11-unix"
        
        // Mining
        $mine1 = "stratum+tcp://"
        $mine2 = "xmrig"
        
        // Spreading
        $spread1 = "masscan"
        $spread2 = "redis-cli"
        $spread3 = "6379" // Redis port
        
        // Evasion
        $hide1 = "LD_PRELOAD"
        $hide2 = "libprocesshider"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            $name or
            (2 of ($mine*) and any of ($spread*)) or
            (any of ($hide*) and any of ($cron*))
        )
}

rule Linux_Miner_TeamTNT
{
    meta:
        description = "Detects TeamTNT cryptominer and cloud credential stealer"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "Targets Docker, Kubernetes, AWS credentials"
        
    strings:
        // TeamTNT indicators
        $tnt1 = "teamtnt" nocase
        $tnt2 = "TNTproxy"
        
        // Docker/Kubernetes targeting
        $docker1 = "docker run"
        $docker2 = "/var/run/docker.sock"
        $k8s1 = "kubectl"
        $k8s2 = "/var/run/secrets/kubernetes.io"
        
        // AWS credential theft
        $aws1 = "/.aws/credentials"
        $aws2 = "aws_access_key_id"
        $aws3 = "169.254.169.254" // AWS metadata
        
        // Mining
        $mine1 = "xmrig"
        $mine2 = "pool.minexmr.com"
        
        // C2
        $c2 = /http:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[a-z]+\.sh/
        
    condition:
        uint32(0) == 0x464c457f and
        (
            any of ($tnt*) or
            (2 of ($docker*, $k8s*) and any of ($mine*)) or
            (2 of ($aws*) and any of ($mine*))
        )
}

rule Linux_Miner_Kinsing
{
    meta:
        description = "Detects Kinsing cryptocurrency miner"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "Targets misconfigured Docker, Redis, Kubernetes"
        
    strings:
        $name = "kinsing" nocase
        
        // Rootkit component
        $rootkit1 = "libprocesshider.so"
        $rootkit2 = "LD_PRELOAD=/usr/local/lib/libprocesshider.so"
        
        // Persistence
        $persist1 = "masscan"
        $persist2 = "pnscan"
        $persist3 = "/etc/ld.so.preload"
        
        // Mining
        $mine1 = "kdevtmpfsi"
        $mine2 = "stratum+tcp"
        
        // Network scan
        $scan1 = "2375" // Docker
        $scan2 = "6379" // Redis
        $scan3 = "8080" // Kubernetes
        
    condition:
        uint32(0) == 0x464c457f and
        (
            $name or
            ($rootkit1 and any of ($mine*)) or
            (2 of ($scan*) and any of ($mine*))
        )
}

rule Linux_Miner_Norman
{
    meta:
        description = "Detects Norman cryptocurrency miner"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        $norman = "norman" nocase
        
        $mine1 = "xmrig"
        $mine2 = "minerd"
        $mine3 = "cpuminer"
        
        $hide1 = "/tmp/."
        $hide2 = "/.X25-"
        
    condition:
        uint32(0) == 0x464c457f and
        ($norman or (2 of ($mine*) and any of ($hide*)))
}

rule Linux_Miner_Generic_Indicators
{
    meta:
        description = "Generic cryptocurrency miner indicators"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "medium"
        
    strings:
        // Common miner names
        $miner1 = "minerd" nocase
        $miner2 = "cpuminer" nocase
        $miner3 = "cryptonight" nocase
        $miner4 = "randomx" nocase
        
        // Pool protocols
        $proto1 = "stratum+tcp://"
        $proto2 = "stratum+ssl://"
        $proto3 = "stratum://"
        
        // Crypto algorithms
        $algo1 = "\"algo\":"
        $algo2 = "cn/r"
        $algo3 = "rx/0"
        $algo4 = "argon2"
        
        // CPU usage
        $cpu1 = "cpu-priority"
        $cpu2 = "threads"
        $cpu3 = "cpu-affinity"
        
        // Hiding behavior
        $hide1 = "/tmp/." // Hidden in /tmp
        $hide2 = "libprocesshider"
        $hide3 = "LD_PRELOAD"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            (any of ($miner*) and any of ($proto*)) or
            (2 of ($algo*) and 2 of ($cpu*)) or
            (any of ($proto*) and any of ($hide*))
        )
}

rule Linux_Miner_Resource_Consumption
{
    meta:
        description = "Detects high resource usage mining behavior"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "medium"
        
    strings:
        // CPU control
        $cpu1 = "nice -n -20"
        $cpu2 = "taskset"
        $cpu3 = "cpu-affinity"
        $cpu4 = "sched_setaffinity"
        
        // Process names
        $proc1 = /[a-z]{8,12}d/ // Generic daemon names
        $proc2 = "kworker"
        $proc3 = "kthreadd"
        
        // Network activity
        $net1 = "443"
        $net2 = "8443"
        $net3 = "3333"
        $net4 = "4444"
        
        // Monero wallet
        $wallet = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/
        
    condition:
        uint32(0) == 0x464c457f and
        2 of ($cpu*) and
        ($wallet or 2 of ($net*))
}

rule Linux_Miner_Cloud_Targeting
{
    meta:
        description = "Detects miners targeting cloud infrastructure"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        // AWS
        $aws1 = "aws_access_key"
        $aws2 = "aws_secret_key"
        $aws3 = "169.254.169.254"
        $aws4 = "/.aws/"
        
        // Docker
        $docker1 = "/var/run/docker.sock"
        $docker2 = "docker ps"
        $docker3 = "docker exec"
        
        // Kubernetes
        $k8s1 = "kubectl"
        $k8s2 = "/var/run/secrets/kubernetes.io"
        $k8s3 = "kube-proxy"
        
        // Mining
        $mine1 = "xmrig"
        $mine2 = "stratum"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            (2 of ($aws*) and any of ($mine*)) or
            (2 of ($docker*) and any of ($mine*)) or
            (2 of ($k8s*) and any of ($mine*))
        )
}
