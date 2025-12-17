"""
Correlation Engine
Aggregates signals from all detection engines and calculates
composite threat scores for ransomware detection
"""

import time
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque


class CorrelationEngine:
    """
    Correlates signals from multiple detection engines:
    - File behavior patterns
    - Process anomalies
    - Command-line threats
    
    Calculates composite threat scores and triggers alerts
    """
    
    # Severity thresholds
    SEVERITY_THRESHOLDS = {
        'low': 30.0,
        'medium': 50.0,
        'high': 70.0,
        'critical': 85.0
    }
    
    # Engine weights for composite scoring
    ENGINE_WEIGHTS = {
        'file_behavior': 0.35,
        'process_monitor': 0.30,
        'cli_monitor': 0.35
    }
    
    def __init__(self,
                 detection_threshold: float = 70.0,
                 correlation_window: int = 30,
                 min_signals: int = 2):
        """
        Initialize Correlation Engine
        
        Args:
            detection_threshold: Composite score to trigger detection
            correlation_window: Time window for signal correlation (seconds)
            min_signals: Minimum signals from different engines to correlate
        """
        self.detection_threshold = detection_threshold
        self.correlation_window = correlation_window
        self.min_signals = min_signals
        
        # Signal storage
        self.signals: Dict[str, deque] = {
            'file_behavior': deque(maxlen=500),
            'process_monitor': deque(maxlen=500),
            'cli_monitor': deque(maxlen=500)
        }
        
        # Detection history
        self.detections: List[Dict] = []
        self.composite_scores: deque = deque(maxlen=1000)
        
        # Statistics
        self.total_signals = 0
        self.correlated_signals = 0
        self.detection_count = 0
        
    def add_signal(self, 
                   engine: str, 
                   signal_type: str,
                   risk_score: float,
                   metadata: Optional[Dict] = None) -> None:
        """
        Add a signal from a detection engine
        
        Args:
            engine: Engine name (file_behavior, process_monitor, cli_monitor)
            signal_type: Type of signal
            risk_score: Risk score from engine (0-100)
            metadata: Additional signal metadata
        """
        if engine not in self.signals:
            return
        
        signal = {
            'engine': engine,
            'type': signal_type,
            'risk_score': risk_score,
            'metadata': metadata or {},
            'timestamp': time.time()
        }
        
        self.signals[engine].append(signal)
        self.total_signals += 1
    
    def get_recent_signals(self, engine: Optional[str] = None) -> List[Dict]:
        """
        Get recent signals within correlation window
        
        Args:
            engine: Specific engine or None for all engines
            
        Returns:
            List of recent signals
        """
        current_time = time.time()
        cutoff_time = current_time - self.correlation_window
        
        recent = []
        
        if engine:
            if engine in self.signals:
                recent = [s for s in self.signals[engine] 
                         if s['timestamp'] >= cutoff_time]
        else:
            for engine_signals in self.signals.values():
                recent.extend([s for s in engine_signals 
                             if s['timestamp'] >= cutoff_time])
        
        return recent
    
    def calculate_composite_score(self) -> Tuple[float, Dict]:
        """
        Calculate composite threat score from all engines
        
        Returns:
            Tuple of (composite_score, signal_breakdown)
        """
        recent_signals = self.get_recent_signals()
        
        if not recent_signals:
            return 0.0, {}
        
        # Calculate weighted scores per engine
        engine_scores = defaultdict(list)
        for signal in recent_signals:
            engine_scores[signal['engine']].append(signal['risk_score'])
        
        # Average scores per engine
        avg_scores = {}
        for engine, scores in engine_scores.items():
            avg_scores[engine] = sum(scores) / len(scores) if scores else 0.0
        
        # Calculate weighted composite
        composite = 0.0
        for engine, weight in self.ENGINE_WEIGHTS.items():
            composite += avg_scores.get(engine, 0.0) * weight
        
        breakdown = {
            'composite_score': composite,
            'engine_scores': avg_scores,
            'signal_counts': {e: len(s) for e, s in engine_scores.items()},
            'total_signals': len(recent_signals),
            'timestamp': time.time()
        }
        
        self.composite_scores.append(breakdown)
        
        return composite, breakdown
    
    def detect_ransomware(self) -> Optional[Dict]:
        """
        Perform ransomware detection based on correlated signals
        
        Returns:
            Detection result if ransomware detected, None otherwise
        """
        # Early return if no recent signals
        recent_signals = self.get_recent_signals()
        if not recent_signals:
            return None
        
        composite, breakdown = self.calculate_composite_score()
        
        # Check if we have signals from multiple engines
        active_engines = len([e for e in breakdown['signal_counts'] 
                            if breakdown['signal_counts'][e] > 0])
        
        if active_engines < self.min_signals:
            return None
        
        # Check threshold
        if composite >= self.detection_threshold:
            severity = self._calculate_severity(composite)
            
            detection = {
                'type': 'ransomware_detection',
                'severity': severity,
                'composite_score': composite,
                'breakdown': breakdown,
                'confidence': self._calculate_confidence(breakdown),
                'timestamp': time.time(),
                'message': f'Ransomware detected: {composite:.1f}% confidence'
            }
            
            self.detections.append(detection)
            self.detection_count += 1
            self.correlated_signals += breakdown['total_signals']
            
            return detection
        
        return None
    
    def _calculate_severity(self, score: float) -> str:
        """Calculate severity level from composite score"""
        if score >= self.SEVERITY_THRESHOLDS['critical']:
            return 'critical'
        elif score >= self.SEVERITY_THRESHOLDS['high']:
            return 'high'
        elif score >= self.SEVERITY_THRESHOLDS['medium']:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_confidence(self, breakdown: Dict) -> float:
        """
        Calculate detection confidence based on signal diversity
        
        Args:
            breakdown: Signal breakdown dictionary
            
        Returns:
            Confidence percentage (0-100)
        """
        # Base confidence from composite score
        base_confidence = breakdown['composite_score']
        
        # Boost for multiple engine correlation
        active_engines = len([e for e in breakdown['signal_counts'] 
                            if breakdown['signal_counts'][e] > 0])
        
        engine_boost = (active_engines - 1) * 5.0  # +5% per additional engine
        
        # Boost for high signal count
        signal_count = breakdown['total_signals']
        signal_boost = min(signal_count * 2.0, 10.0)  # Max +10%
        
        confidence = min(base_confidence + engine_boost + signal_boost, 99.9)
        
        return round(confidence, 1)
    
    def get_threat_trend(self, duration: int = 60) -> List[float]:
        """
        Get threat score trend over time
        
        Args:
            duration: Time period in seconds
            
        Returns:
            List of composite scores over time
        """
        current_time = time.time()
        cutoff_time = current_time - duration
        
        recent_scores = [
            score['composite_score'] 
            for score in self.composite_scores
            if score['timestamp'] >= cutoff_time
        ]
        
        return recent_scores
    
    def is_threat_escalating(self, threshold_increase: float = 20.0) -> bool:
        """
        Check if threat is escalating
        
        Args:
            threshold_increase: % increase to consider escalating
            
        Returns:
            True if threat is escalating
        """
        trend = self.get_threat_trend(duration=30)
        
        if len(trend) < 2:
            return False
        
        # Compare recent average to older average
        mid_point = len(trend) // 2
        old_avg = sum(trend[:mid_point]) / mid_point if mid_point > 0 else 0
        new_avg = sum(trend[mid_point:]) / (len(trend) - mid_point)
        
        if old_avg == 0:
            return new_avg > threshold_increase
        
        increase_pct = ((new_avg - old_avg) / old_avg) * 100
        
        return increase_pct >= threshold_increase
    
    def get_signal_summary(self) -> Dict:
        """Get summary of signals by engine"""
        summary = {}
        
        for engine, signals in self.signals.items():
            recent = self.get_recent_signals(engine)
            
            summary[engine] = {
                'total_signals': len(signals),
                'recent_signals': len(recent),
                'avg_risk_score': (sum(s['risk_score'] for s in recent) / len(recent)) 
                                 if recent else 0.0
            }
        
        return summary
    
    def get_statistics(self) -> Dict:
        """Get correlation engine statistics"""
        composite, _ = self.calculate_composite_score()
        
        return {
            'total_signals': self.total_signals,
            'correlated_signals': self.correlated_signals,
            'detection_count': self.detection_count,
            'current_composite_score': composite,
            'threat_escalating': self.is_threat_escalating(),
            'signal_summary': self.get_signal_summary()
        }
    
    def reset(self) -> None:
        """Reset engine state"""
        for engine_signals in self.signals.values():
            engine_signals.clear()
        
        self.detections.clear()
        self.composite_scores.clear()
        self.total_signals = 0
        self.correlated_signals = 0
        self.detection_count = 0
