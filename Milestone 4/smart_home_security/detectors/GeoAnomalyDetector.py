from typing import Dict, Optional, Tuple, List, Set, Any
from datetime import datetime, timedelta
import geoip2.database
import ipaddress

class GeoAnomalyDetector:
    def __init__(self, 
                 max_speed_kmh: float = 900,  # Commercial airliner speed
                 geoip_db_path: str = 'smart_home_security/detectors/GeoLite2-City.mmdb',
                 blacklist_countries: Set[str] = None,
                 tor_exit_nodes: Set[str] = None,
                 mock_locations: Dict[str, Tuple[float, float, str]] = None):
        """
        Initialize detector with:
        - max_speed_kmh: maximum plausible travel speed (km/h)
        - geoip_db_path: path to MaxMind GeoIP2 database
        - blacklist_countries: set of country codes to block
        - tor_exit_nodes: set of known TOR exit node IPs
        - mock_locations: dict of IP -> (lat, lon, country) for testing
        """
        self.max_speed_kmh = max_speed_kmh
        self.geoip_reader = geoip2.database.Reader(geoip_db_path)
        self.blacklist_countries = blacklist_countries or set()
        self.tor_exit_nodes = tor_exit_nodes or set()
        self.mock_locations = mock_locations or {}
        self.user_locations: Dict[str, List[Tuple[datetime, float, float]]] = {}
    
    def _get_location(self, ip_address: str) -> Tuple[Optional[float], Optional[float], Optional[str]]:
        """Get (lat, lon, country_code) from IP address"""
        # Check mock data first for testing
        if ip_address in self.mock_locations:
            return self.mock_locations[ip_address]
        
        try:
            response = self.geoip_reader.city(ip_address)
            return (response.location.latitude, 
                    response.location.longitude, 
                    response.country.iso_code)
        except:
            return None, None, None
    
    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points in km (Haversine formula)"""
        from math import radians, sin, cos, sqrt, atan2
        
        R = 6371.0  # Earth radius in km
        
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        
        return R * c
    
    def detect(self, user_id: str, ip_address: str, timestamp: datetime) -> Tuple[bool, Optional[str]]:
        """Detect geographic anomalies"""
        # Check for blacklisted IPs first
        if ip_address in self.tor_exit_nodes:
            return True, f"Access from known TOR exit node {ip_address}"
        
        # Get current location
        curr_lat, curr_lon, country_code = self._get_location(ip_address)
        
        # Check for blacklisted country
        if country_code and country_code in self.blacklist_countries:
            return True, f"Access from blacklisted country {country_code}"
        
        # If we can't determine location, skip further checks
        if curr_lat is None or curr_lon is None:
            return False, None
        
        # Initialize user location history if needed
        if user_id not in self.user_locations:
            self.user_locations[user_id] = []
        
        # Check for impossible travel
        anomaly_detected = False
        message = None
        
        for prev_time, prev_lat, prev_lon in self.user_locations[user_id]:
            time_diff = (timestamp - prev_time).total_seconds() / 3600  # hours
            if time_diff <= 0:
                continue  # Skip same or future timestamps
            
            distance = self._calculate_distance(prev_lat, prev_lon, curr_lat, curr_lon)
            speed = distance / time_diff  # km/h
            
            if speed > self.max_speed_kmh:
                anomaly_detected = True
                message = (f"Impossible travel detected for {user_id}: "
                         f"{distance:.1f} km in {time_diff*60:.1f} minutes "
                         f"(speed: {speed:.1f} km/h)")
                break
        
        # Add current location to history
        self.user_locations[user_id].append((timestamp, curr_lat, curr_lon))
        
        # Keep only recent locations (last 24 hours)
        self.user_locations[user_id] = [
            loc for loc in self.user_locations[user_id]
            if (timestamp - loc[0]) < timedelta(hours=24)
        ]
        
        return anomaly_detected, message
    
    def get_event_data(self, user_id: str, ip_address: str, timestamp: str, 
                      message: str) -> Dict[str, Any]:
        return {
            "timestamp": timestamp,
            "event": "geo_anomaly",
            "user_id": user_id,
            "ip_address": ip_address,
            "message": message
        }
    
    def refresh_tor_exit_nodes(self):
        """Refresh the list of known TOR exit nodes"""
        import requests
        try:
            response = requests.get('https://check.torproject.org/torbulkexitlist')
            self.tor_exit_nodes = set(response.text.splitlines())
        except:
            pass  # Keep existing list if refresh fails