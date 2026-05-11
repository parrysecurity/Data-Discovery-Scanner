import re

class DetectionPatterns:
    """Sensitive data detection patterns"""
    
    PATTERNS = {
        'email': {
            'regex': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'risk_level': 'low',
            'risk_score': 3,
            'description': 'Email address'
        },
        'ssn': {
            'regex': r'\b\d{3}-\d{2}-\d{4}\b',
            'risk_level': 'high',
            'risk_score': 8,
            'description': 'Social Security Number'
        },
        'credit_card_visa': {
            'regex': r'\b4[0-9]{12}(?:[0-9]{3})?\b',
            'risk_level': 'critical',
            'risk_score': 10,
            'description': 'Visa credit card number'
        },
        'credit_card_mastercard': {
            'regex': r'\b5[1-5][0-9]{14}\b',
            'risk_level': 'critical',
            'risk_score': 10,
            'description': 'Mastercard credit card number'
        },
        'credit_card_amex': {
            'regex': r'\b3[47][0-9]{13}\b',
            'risk_level': 'critical',
            'risk_score': 10,
            'description': 'American Express card number'
        },
        'credit_card_discover': {
            'regex': r'\b6(?:011|5[0-9]{2})[0-9]{12}\b',
            'risk_level': 'critical',
            'risk_score': 10,
            'description': 'Discover card number'
        },
        'api_key_google': {
            'regex': r'AIza[0-9A-Za-z\-_]{35}',
            'risk_level': 'critical',
            'risk_score': 10,
            'description': 'Google API key'
        },
        'api_key_aws': {
            'regex': r'AKIA[0-9A-Z]{16}',
            'risk_level': 'critical',
            'risk_score': 10,
            'description': 'AWS Access Key'
        },
        'api_key_stripe': {
            'regex': r'sk_live_[0-9a-zA-Z]{24}',
            'risk_level': 'critical',
            'risk_score': 10,
            'description': 'Stripe Secret Key'
        },
        'api_key_github': {
            'regex': r'gh[ops]_[0-9a-zA-Z]{36}',
            'risk_level': 'critical',
            'risk_score': 10,
            'description': 'GitHub Token'
        },
        'jwt_token': {
            'regex': r'eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+',
            'risk_level': 'high',
            'risk_score': 9,
            'description': 'JWT Token'
        },
        'ip_address': {
            'regex': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'risk_level': 'medium',
            'risk_score': 5,
            'description': 'IP Address'
        },
        'phone_number': {
            'regex': r'\b(?:\+?1?[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
            'risk_level': 'medium',
            'risk_score': 5,
            'description': 'Phone number'
        },
        'password_plain': {
            'regex': r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"]?[^\s\'"]+[\'"]?',
            'risk_level': 'critical',
            'risk_score': 10,
            'description': 'Plaintext password'
        },
        'connection_string': {
            'regex': r'(mongodb|mysql|postgresql|redis)://[^\s]+',
            'risk_level': 'critical',
            'risk_score': 10,
            'description': 'Database connection string'
        }
    }
    
    @staticmethod
    def validate_credit_card(number):
        """Luhn algorithm validation for credit cards"""
        from luhn import Luhn
        try:
            return Luhn(number).is_valid()
        except:
            return False
    
    @staticmethod
    def redact_value(value, data_type):
        """Redact sensitive values for display"""
        if 'credit_card' in data_type:
            return f"****-****-****-{value[-4:]}" if len(value) >= 4 else "***REDACTED***"
        elif 'email' in data_type:
            parts = value.split('@')
            return f"{parts[0][:2]}***@{parts[1]}" if len(parts[0]) > 2 else "***@***"
        elif 'ssn' in data_type:
            return f"***-**-{value[-4:]}" if len(value) >= 4 else "***-**-****"
        elif 'api_key' in data_type:
            return f"{value[:8]}...{value[-4:]}" if len(value) > 12 else "***REDACTED***"
        else:
            return value[:4] + "..." + value[-4:] if len(value) > 8 else "***REDACTED***"
