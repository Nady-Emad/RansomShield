"""
Correlation and AI-based threat scoring engine.
Multi-signal analysis inspired by CrowdStrike and SentinelOne.
"""

import logging
from datetime import datetime
from collections import deque

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
    Multi-signal threat correlation.
    Inspired by CrowdStrike Threat Graph & Palo Alto XDR.
    """
    
    def __init__(self):
        self.file_engine = None
        self.process_engine = None
        self.cli_engine = None
        self.threat_history = deque(maxlen=10000)
        self.sensitivity = 'medium'
        self.score_weights = {
            'file': 0.50,      # File behavior most critical
            'process': 0.30,   # CPU/IO patterns
            'cli': 0.20,       # Background indicators
        }
    
    def correlate_threat(self, pid, process_name):
        """
        Correlate signals from all engines.
        Returns final threat score and recommendation.
        """
        
        # Get scores from each engine
        file_score = self.file_engine.score_process(pid) if self.file_engine else 0
        process_score = self.process_engine.score_process_activity(pid) if self.process_engine else 0
        
        # Weighted correlation
        composite_score = (
            file_score * self.score_weights['file'] +
            process_score * self.score_weights['process']
        )
        
        # Penalty multiplier if backup tampering detected
        if self.cli_engine and self.cli_engine.detected_commands:
            if any(c['pid'] == pid for c in self.cli_engine.detected_commands):
                composite_score = min(100, composite_score * 1.5)  # 50% boost
        
        composite_score = min(composite_score, 100)
        
        # Determine action
        action = self._get_recommended_action(composite_score)
        threat_level = self._get_threat_level(composite_score)
        
        threat_data = {
            'pid': pid,
            'process_name': process_name,
            'composite_score': composite_score,
            'file_score': file_score,
            'process_score': process_score,
            'threat_level': threat_level,
            'recommended_action': action,
            'timestamp': datetime.now().isoformat(),
        }
        
        self.threat_history.append(threat_data)
        return threat_data
    
    def _get_recommended_action(self, score):
        """Get recommended action based on threat score."""
        if score >= 85:
            return 'KILL_PROCESS'
        elif score >= 70:
            return 'BLOCK_WRITES'
        elif score >= 50:
            return 'ALERT'
        else:
            return 'MONITOR'
    
    def _get_threat_level(self, score):
        """Get threat level string."""
        if score >= 85:
            return 'CRITICAL'
        elif score >= 70:
            return 'HIGH'
        elif score >= 50:
            return 'MEDIUM'
        elif score >= 25:
            return 'LOW'
        else:
            return 'INFO'
    
    def set_sensitivity(self, level):
        """Adjust correlation sensitivity."""
        if level == 'high':
            self.score_weights['file'] = 0.60
            self.score_weights['process'] = 0.25
            self.score_weights['cli'] = 0.15
        elif level == 'low':
            self.score_weights['file'] = 0.40
            self.score_weights['process'] = 0.35
            self.score_weights['cli'] = 0.25
        else:  # medium
            self.score_weights['file'] = 0.50
            self.score_weights['process'] = 0.30
            self.score_weights['cli'] = 0.20
        self.sensitivity = level
