package types

type CEngineVerdict struct {
	Alpha     float64 `json:"alpha"`
	Beta      float64 `json:"beta"`
	Gamma     float64 `json:"gamma"`
	Consensus float64 `json:"consensus"`
	Threshold float64 `json:"threshold"`
	Hostile   int     `json:"hostile"`
	Audit     Audit   `json:"audit"`
}

type Audit struct {
	SpoofDetected    int     `json:"spoof_detected"`
	TorVpnProxy      int     `json:"tor_vpn_proxy"`
	Datacenter       int     `json:"datacenter"`
	SpoofedUA        int     `json:"spoofed_ua"`
	Confidence       float64 `json:"confidence"`
	ThreatResonance  float64 `json:"threat_resonance"`
	RequiresLLM      int     `json:"requires_llm"`
	SpoofScore       float64 `json:"spoof_score"`
	TorVpnScore      float64 `json:"tor_vpn_score"`
	AutomationScore  float64 `json:"automation_score"`
	TlsRiskScore     float64 `json:"tls_risk_score"`
	CampaignScore    float64 `json:"campaign_score"`
	EvidenceQuality  float64 `json:"evidence_quality"`
	ForensicScore    float64 `json:"forensic_score"`
	AuditorHostile   int     `json:"auditor_hostile"`
}

type ClassifyResult struct {
	Hostile    int     `json:"hostile"`
	Consensus  float64 `json:"consensus"`
	Alpha      float64 `json:"alpha"`
	Beta       float64 `json:"beta"`
	Gamma      float64 `json:"gamma"`
	Tier       int     `json:"tier"`
	Actor      string  `json:"actor"`
	Fingerprint string `json:"fingerprint"`
	Trusted    bool    `json:"trusted"`
	Reason     string  `json:"reason"`
	Error      string  `json:"error,omitempty"`
}

type GeoIPResult struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	City    string `json:"city"`
	ASN     string `json:"asn"`
	ISP     string `json:"isp"`
	Hosting bool   `json:"hosting"`
}

type FBIEvidence struct {
	Timestamp        string            `json:"timestamp"`
	CaseID           string            `json:"case_id"`
	Classification   string            `json:"classification"`
	EventType        string            `json:"event_type"`
	IP               string            `json:"ip"`
	Reason           string            `json:"reason"`
	ThreatScore      int               `json:"threat_score"`
	TriadScores      TriadScores       `json:"triad_scores"`
	Geo              GeoIPResult       `json:"geo"`
	TCPDNA           TCPDNA            `json:"tcp_dna"`
	MITREAttackIDs   []string          `json:"mitre_attack_ids"`
	EvidenceChainHash string           `json:"evidence_chain_hash"`
	PreviousHash     string            `json:"previous_hash"`
}

type TriadScores struct {
	Shield    float64 `json:"shield"`
	Audit     float64 `json:"audit"`
	Soul      float64 `json:"soul"`
	Consensus float64 `json:"consensus"`
	Final     int     `json:"final"`
}

type TCPDNA struct {
	TTL    int    `json:"ttl"`
	Window int    `json:"window"`
	MSS    int    `json:"mss"`
	JA3    string `json:"ja3"`
}

type Campaign struct {
	IP            string  `json:"ip"`
	Country       string  `json:"country"`
	ISP           string  `json:"isp"`
	Hosting       bool    `json:"hosting"`
	PriorStrikes  int     `json:"prior_strikes"`
	Cluster       string  `json:"cluster,omitempty"`
	CampaignScore float64 `json:"campaign_score"`
}

type LLMRequest struct {
	Model    string      `json:"model"`
	Messages []LLMMessage `json:"messages"`
	MaxTokens int        `json:"max_tokens"`
}

type LLMMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type LLMResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

type ShieldCheckParams struct {
	IP    string `json:"ip"`
	Path  string `json:"path"`
	UA    string `json:"ua"`
	Method string `json:"method"`
	RulesScore  int      `json:"rules_score"`
	RulesReasons []string `json:"rules_reasons"`
}
