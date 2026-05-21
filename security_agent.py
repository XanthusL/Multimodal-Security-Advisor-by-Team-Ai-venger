import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict
from models import *
import hashlib


class SecurityAgent:
    def __init__(self):
        self.event_history = []  # Store recent events
        self.person_tracking = {}  # Track individuals across zones
        self.bias_audit_log = []  # For fairness auditing

    def _check_correlated_motions(self, motion_signals: List[Signal]) -> int:
        """Check if multiple motion sensors are triggered in nearby areas"""
        # Count unique sensor locations
        locations = set(s.location for s in motion_signals)
        return len(locations)

    def analyze_signal_fusion(
        self, signals: List[Signal], context: SecurityContext
    ) -> ThreatLevel:

        for signal in signals:
            if signal.type in [
                EventType.GUNSHOT_AUDIO,
                EventType.EXPLOSION,
                EventType.FIRE,
                EventType.ARSON,
            ]:
                return ThreatLevel.CRITICAL  # Explosion = CRITICAL!
            if signal.type in [EventType.PANIC_CALL, EventType.FORCED_ENTRY]:
                # Panic calls and forced entries are always HIGH threat
                return ThreatLevel.HIGH
            if signal.type == EventType.UNAUTHORIZED_ACCESS:
                return ThreatLevel.HIGH
        """
        Signal fusion & conflict resolution logic
        """
        # High-confidence single signal vs multiple low-confidence
        high_conf_signals = [s for s in signals if s.confidence > 80]

        for signal in high_conf_signals:
            if signal.type == EventType.GUNSHOT_AUDIO:
                # Gunshot overrides everything - cost of inaction too high
                return ThreatLevel.CRITICAL

        # Conflict: motion sensors fire but CCTV shows nothing
        motion_signals = [s for s in signals if s.type == EventType.MOTION_DETECTION]
        has_cctv_evidence = any(
            s.type in [EventType.UNAUTHORIZED_ACCESS, EventType.FORCED_ENTRY]
            for s in signals
        )

        if motion_signals and not has_cctv_evidence:
            if context.zone_type == "high_security":
                # Check for video looping or other motion sensors
                nearby_motions = self._check_correlated_motions(motion_signals)
                if nearby_motions > 2:
                    return ThreatLevel.HIGH
                else:
                    return ThreatLevel.MEDIUM
            else:
                # Low security area - likely false alarm
                return ThreatLevel.LOW

        # Distinguish genuine incident from correlated noise (storm)
        return self._detect_correlated_noise(signals, context)

    def _detect_correlated_noise(
        self, signals: List[Signal], context: SecurityContext
    ) -> ThreatLevel:
        """
        Distinguish real incident from storm/animal triggers
        """
        # Check signal characteristics
        has_impact_signature = any(
            s.metadata.get("frequency") == "high"
            and s.metadata.get("duration") == "brief"
            for s in signals
        )

        has_rumble_signature = any(
            s.metadata.get("frequency") == "low"
            and s.metadata.get("duration") == "long"
            for s in signals
        )

        # Wide/global trigger area suggests environmental cause
        locations = set(s.location for s in signals)
        if len(locations) > 3 and has_rumble_signature:
            return ThreatLevel.LOW  # Likely storm

        # Localized sequential triggers suggest real incident
        if has_impact_signature and len(locations) <= 2:
            return ThreatLevel.HIGH

        return ThreatLevel.MEDIUM

    def temporal_reasoning(
        self, signals: List[Signal], context: SecurityContext
    ) -> Dict:
        """
        Temporal analysis - different windows for different situations
        """
        now = datetime.now()

        # Determine lookback window based on event type
        urgent_events = [
            EventType.FORCED_ENTRY,
            EventType.PANIC_CALL,
            EventType.GUNSHOT_AUDIO,
        ]
        pattern_events = [EventType.FAILED_BADGE, EventType.DOOR_CONTACT]
        behavioral_events = [EventType.LOITERING]

        if any(s.type in urgent_events for s in signals):
            window = timedelta(
                minutes=5
            )  # Immediate response needs only last few minutes
            requires_immediate = True
        elif any(s.type in pattern_events for s in signals):
            window = timedelta(minutes=30)  # Look for patterns
            requires_immediate = False
        elif any(s.type in behavioral_events for s in signals):
            window = timedelta(hours=2)  # Longer for loitering detection
            requires_immediate = False
        else:
            window = timedelta(hours=24)  # Full day for repeated behaviors
            requires_immediate = False

        # Filter events within window
        recent_events = [s for s in signals if s.timestamp > now - window]

        # Check for sequences (e.g., failed badge → propped door → motion)
        sequence_detected = self._detect_sequence(
            recent_events,
            [
                EventType.FAILED_BADGE,
                EventType.DOOR_CONTACT,
                EventType.MOTION_DETECTION,
            ],
        )

        return {
            "window_minutes": int(window.total_seconds() / 60),
            "requires_immediate": requires_immediate,
            "sequence_detected": sequence_detected,
            "event_count": len(recent_events),
            "pattern_forming": len(recent_events) >= 3,
        }

    def _detect_sequence(self, events: List[Signal], sequence: List[EventType]) -> bool:
        """Check if events follow a specific sequence"""
        event_types = [e.type for e in events]
        # Check if sequence appears in order
        for i in range(len(event_types) - len(sequence) + 1):
            if event_types[i : i + len(sequence)] == sequence:
                return True
        return False

    def track_person_across_zones(
        self,
        person_id: str,
        camera_zone: str,
        timestamp: datetime,
        similarity_score: float,
    ) -> Dict:
        """
        Track same person across multiple camera zones
        """
        if person_id not in self.person_tracking:
            self.person_tracking[person_id] = {
                "zones_visited": [],
                "first_seen": timestamp,
                "last_seen": timestamp,
                "total_time_minutes": 0,
                "last_zone": camera_zone,
            }

        tracking = self.person_tracking[person_id]
        time_gap = (timestamp - tracking["last_seen"]).total_seconds() / 60

        # Check if physically possible to move between zones
        if time_gap < 5 and similarity_score > 0.7:
            # Same person, continue tracking
            tracking["zones_visited"].append(camera_zone)
            tracking["last_seen"] = timestamp
            tracking["total_time_minutes"] += time_gap
        else:
            # Too long gap or low similarity - treat as different
            return {"is_same_person": False, "reset_timer": True}

        return {
            "is_same_person": True,
            "total_time_minutes": tracking["total_time_minutes"],
            "zones_visited": tracking["zones_visited"],
        }

    def proportionality_encoding(
        self, threat_level: ThreatLevel, confidence: float, context: SecurityContext, signals: List[Signal] = None
    ) -> Recommendation:
        threat_score = self._calculate_threat_score(threat_level, confidence, context)

        # Determine urgency and approval requirement based on threat level
        if threat_level == ThreatLevel.CRITICAL:
            urgency = "immediate"
            requires_approval = True
        elif threat_score > 45:
            urgency = "immediate"
            requires_approval = False
        elif threat_score > 20:
            urgency = "soon"
            requires_approval = False
        else:
            urgency = "monitor"
            requires_approval = False

        # Determine visual cue based on threat level
        if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            visual_cue = "🔴 RED"
        elif threat_level == ThreatLevel.MEDIUM:
            visual_cue = "🟡 YELLOW"
        else:
            visual_cue = "🟢 GREEN"

        # Generate SOP steps
        sop_steps = self._generate_sop_steps(threat_level, context, signals or [])

        # Generate proportionality rationale
        proportionality_rationale = self._generate_proportionality_rationale(
            threat_level, confidence, context, sop_steps, signals or []
        )

        # Generate guideline reference
        guideline_reference = self._generate_guideline_reference(threat_level, signals or [])

        # Determine primary action for reasoning field
        primary_action = sop_steps[0].split(". ", 1)[1] if sop_steps else "Continue monitoring"

        return Recommendation(
            sop_steps=sop_steps,
            urgency=urgency,
            requires_human_approval=requires_approval,
            confidence=ConfidenceScore(
                classification=threat_level.value,
                confidence=confidence,
                alternative=self._get_alternative_scenario(threat_level, context),
                alternative_confidence=100 - confidence,
            ),
            reasoning=f"Threat score {threat_score:.0f}: {primary_action}",
            visual_cue=visual_cue,
            proportionality_rationale=proportionality_rationale,
            guideline_reference=guideline_reference,
        )

    def _calculate_threat_score(
        self, threat_level: ThreatLevel, confidence: float, context: SecurityContext
    ) -> float:
        base_scores = {
            ThreatLevel.CRITICAL: 95,
            ThreatLevel.HIGH: 75,
            ThreatLevel.MEDIUM: 50,
            ThreatLevel.LOW: 25,
        }

        score = base_scores[threat_level] * (confidence / 100)

        # Zone adjustment
        if context.zone_type == "high_security":
            score *= 1.2
        elif context.zone_type == "critical_infrastructure":
            score *= 1.5
        elif context.zone_type == "public_space":
            score *= 0.8

        return min(100, max(0, score))

    def _get_alternative_scenario(
        self, threat_level: ThreatLevel, context: SecurityContext
    ) -> str:
        """Provide alternative explanation for low confidence"""
        if threat_level == ThreatLevel.HIGH:
            return "delivery person or maintenance staff"
        elif threat_level == ThreatLevel.MEDIUM:
            return "authorized personnel after hours"
        else:
            return "environmental trigger (animal, weather)"

    def _generate_sop_steps(
        self, threat_level: ThreatLevel, context: SecurityContext, signals: List[Signal]
    ) -> List[str]:
        """
        Generate numbered SOP steps (3-5 items) specific to threat level and zone.
        Each step is an actionable task the officer must complete in order.
        """
        zone_ref = context.zone_type.upper()
        
        if threat_level == ThreatLevel.CRITICAL:
            return [
                "1. Activate emergency lockdown protocol immediately - secure all exits.",
                "2. Dispatch ALL available units to PRIMARY affected zone.",
                "3. Establish incident command post and begin real-time coordinated response.",
                "4. Log all sensor sources, timestamps, and officer positions in incident tracker.",
                "5. Establish hot line to executive security and law enforcement liaison.",
            ]
        elif threat_level == ThreatLevel.HIGH:
            return [
                "1. Radio duty supervisor immediately with threat details and location.",
                f"2. Dispatch nearest guard to {zone_ref} for visual verification.",
                "3. Lock down adjacent access points pending confirmation.",
                "4. Begin incident log entry with timestamp and sensor sources.",
            ]
        elif threat_level == ThreatLevel.MEDIUM:
            return [
                "1. Alert supervisor of elevated threat status and sensor details.",
                "2. Increase patrol frequency in affected area over next 30 minutes.",
                "3. Document signal sources and confidence levels in security log.",
                "4. Prepare for potential escalation if additional signals arrive.",
            ]
        else:  # LOW
            return [
                "1. Continue passive monitoring of affected zone.",
                "2. Note sensor trigger in routine daily log.",
                "3. Monitor for pattern emergence or signal reinforcement.",
            ]

    def _generate_guideline_reference(
        self, threat_level: ThreatLevel, signals: List[Signal]
    ) -> str:
        """
        Generate regulatory/policy guideline reference based on threat level and event types.
        Mapping:
        - Fire/smoke → SCDF Emergency Response Guidelines
        - Unauthorised access / intrusion → CPNI Physical Security
        - Medical / panic → MOM Workplace Safety and Health Act
        - General elevated threat → SS 545: Singapore Standard
        - Low / monitoring → MHA Security Guidelines
        """
        if not signals:
            if threat_level == ThreatLevel.LOW:
                return "MHA Security Guidelines for Buildings"
            elif threat_level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                return "SS 545: Singapore Standard for Security Risk Management"
            return "MHA Security Guidelines for Buildings"
        
        # Check event types in signals
        event_types = {s.type for s in signals}
        
        # Fire/smoke priority
        if any(et in event_types for et in [EventType.FIRE, EventType.SMOKE, EventType.ARSON, EventType.EXPLOSION]):
            return "SCDF Emergency Response Guidelines (Singapore Civil Defence Force)"
        
        # Medical/panic priority
        if EventType.PANIC_CALL in event_types:
            return "MOM Workplace Safety and Health Act — Emergency Procedures"
        
        # Unauthorised access/intrusion
        if any(et in event_types for et in [EventType.UNAUTHORIZED_ACCESS, EventType.FORCED_ENTRY]):
            return "CPNI Physical Security: Responding to Security Breaches"
        
        # General threat levels
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            return "SS 545: Singapore Standard for Security Risk Management"
        elif threat_level == ThreatLevel.MEDIUM:
            return "SS 545: Singapore Standard for Security Risk Management"
        else:  # LOW
            return "MHA Security Guidelines for Buildings"

    def _generate_proportionality_rationale(
        self, threat_level: ThreatLevel, confidence: float, context: SecurityContext, sop_steps: List[str], signals: List[Signal]
    ) -> str:
        """
        Generate a 2-3 sentence explanation of why the response level is proportionate.
        Consider: zone type, number of corroborating signals, confidence score, and time of day.
        """
        zone_desc = {
            "high_security": "critical infrastructure zone",
            "critical_infrastructure": "critical infrastructure zone",
            "blind_spot": "unsupervised area",
            "public_space": "public area",
            "low_security": "low-security area",
        }.get(context.zone_type, "monitored zone")
        
        signal_count = len(signals)
        corroborating_count = sum(1 for s in signals if s.confidence > 70)
        time_of_day = context.time_of_day
        
        # Build rationale based on threat level and factors
        if threat_level == ThreatLevel.CRITICAL:
            return (
                f"Full lockdown is necessary given the critical threat. "
                f"With {corroborating_count} high-confidence corroborating signals and {confidence:.0f}% confidence in the {zone_desc}, "
                f"the cost of inaction far exceeds any operational disruption per CPNI protocols."
            )
        elif threat_level == ThreatLevel.HIGH:
            rationale_parts = []
            rationale_parts.append(f"Guard verification is proportionate for a high-threat incident in a {zone_desc}.")
            if corroborating_count >= 2:
                rationale_parts.append(f"Multiple signals ({corroborating_count}) corroborate the threat at {confidence:.0f}% confidence.")
            else:
                rationale_parts.append(f"Single signal with {confidence:.0f}% confidence warrants immediate assessment to rule out false alarm.")
            rationale_parts.append("This minimal response meets CPNI physical security guidelines without excessive escalation.")
            return " ".join(rationale_parts)
        elif threat_level == ThreatLevel.MEDIUM:
            if signal_count > 2:
                return (
                    f"Increased monitoring is proportionate given {signal_count} signals in the {zone_desc}. "
                    f"With {confidence:.0f}% confidence and only {corroborating_count} confirmed sources, supervisor notification enables human judgment "
                    f"without premature deployment during {time_of_day} hours."
                )
            else:
                return (
                    f"Enhanced monitoring balances security and operational continuity for a medium-threat assessment. "
                    f"One weak signal ({confidence:.0f}% confidence) in the {zone_desc} requires supervisory awareness but not immediate response."
                )
        else:  # LOW
            return (
                f"Passive monitoring is appropriate for low-threat signals in the {zone_desc} at {confidence:.0f}% confidence. "
                f"No corroborating evidence of actual breach; continued observation aligns with baseline security posture. "
                f"Escalation only if patterns emerge or signals strengthen."
            )

    def detect_sensor_attack(self, signals: List[Signal]) -> Optional[str]:
        """
        Detect deliberate sensor tampering
        """
        # Camera obstruction detection
        for signal in signals:
            if signal.type == EventType.CAMERA_OBSTRUCTION:
                return f"ALERT: Camera at {signal.location} is deliberately obscured - dispatch human verification"

        # Access card cloning detection
        card_events = [s for s in signals if s.type == EventType.FAILED_BADGE]
        if len(card_events) > 5:
            unique_locations = set(e.location for e in card_events)
            if len(unique_locations) > 2:
                return "ALERT: Potential access card cloning detected - flag card and notify owner"

        return None

    def graceful_degradation(self, active_streams: int, total_streams: int = 6) -> Dict:
        """
        Handle offline sensors gracefully
        """
        if active_streams >= 5:
            return {"mode": "normal", "confidence_multiplier": 1.0}
        elif active_streams >= 3:
            return {
                "mode": "degraded",
                "confidence_multiplier": 0.7,
                "message": "⚠️ Limited visibility - increase patrol frequency",
            }
        else:
            return {
                "mode": "minimal",
                "confidence_multiplier": 0.3,
                "message": "🔴 CRITICAL: Multiple sensors offline - switch to manual patrols",
                "recommendation": "Deploy security personnel for physical verification",
            }

    def audit_bias(self, decision_log: List[Dict]) -> Dict:
        """
        Audit for discriminatory patterns
        """
        if not decision_log:
            return {"message": "No decision log data available for audit"}

        # Group by demographics (would need actual demographic data)
        demographic_groups = {}

        for decision in decision_log:
            demo = decision.get("demographic", "unknown")
            if demo not in demographic_groups:
                demographic_groups[demo] = {
                    "true_positives": 0,
                    "false_positives": 0,
                    "total": 0,
                }

            demographic_groups[demo]["total"] += 1
            if decision.get("was_correct", False):
                demographic_groups[demo]["true_positives"] += 1
            else:
                demographic_groups[demo]["false_positives"] += 1

        # Calculate false positive rates
        audit_results = {}
        for demo, stats in demographic_groups.items():
            fpr = stats["false_positives"] / stats["total"] if stats["total"] > 0 else 0
            audit_results[demo] = {
                "false_positive_rate": fpr,
                "total_decisions": stats["total"],
                "bias_risk": (
                    "HIGH" if fpr > 0.15 else "MEDIUM" if fpr > 0.08 else "LOW"
                ),
            }

        return audit_results
