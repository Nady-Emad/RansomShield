"""Risk scoring engine - Dynamic threat scoring with time decay.

Features:
- Cumulative risk scoring
- Automatic score decay over time (configurable)
- Score normalization (0-100)
- Threat level classification
- Comprehensive error handling

Scoring:
- Each detection adds points
- Points decay at configured rate per minute
- Maximum score: 100
- Score resets on resolution
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any


class RiskEngine:
    """Risk scoring engine with temporal decay."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize risk engine.
        
        Args:
            config: Configuration dict with 'score_decay_per_minute'
        """
        self.config = config or {'score_decay_per_minute': 1.0}
        self.current_score: float = 0.0
        self.last_increase_time: datetime = datetime.now()
    
    def add_score(self, points: float) -> None:
        """Increase risk score.
        
        Args:
            points: Points to add (positive)
        """
        try:
            if not isinstance(points, (int, float)) or points < 0:
                return
            
            self.current_score = min(100.0, self.current_score + float(points))
            self.last_increase_time = datetime.now()
        except (TypeError, ValueError):
            pass
    
    def decay_score(self) -> float:
        """Decay score over time.
        
        Returns:
            Current score after decay
        """
        try:
            elapsed_minutes = (datetime.now() - self.last_increase_time).total_seconds() / 60.0
            decay_rate = self.config.get('score_decay_per_minute', 1.0)
            
            if isinstance(decay_rate, (int, float)):
                decay = max(0.0, decay_rate * elapsed_minutes)
                self.current_score = max(0.0, self.current_score - decay)
            
            return self.current_score
        except (TypeError, ValueError):
            return self.current_score
        except Exception:
            return self.current_score
    
    def get_threat_level(self) -> str:
        """Get threat level based on current score.
        
        Returns:
            Threat level: CRITICAL, HIGH, MEDIUM, LOW, or INFO
        """
        score = self.current_score
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
    
    def reset(self) -> None:
        """Reset score to zero."""
        self.current_score = 0.0
        self.last_increase_time = datetime.now()
