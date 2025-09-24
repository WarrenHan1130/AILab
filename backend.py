from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
import sqlite3
import hashlib
import secrets
import json
import time
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import numpy as np
import threading
from contextlib import contextmanager
import uuid
import groq
from groq import Groq
import re

class SystemConfig:
    DB_PATH = "secure_bank.db"
    LOG_FILE = "security_audit.log"
    SESSION_TIMEOUT = 3600
    MAX_LOGIN_ATTEMPTS = 5
    RATE_LIMIT_WINDOW = 60
    ADMIN_BYPASS_CODE = "SB_ADMIN_2024_OVERRIDE"
    DEBUG_TOKEN = "DEBUG_ENABLED_2024"
    ENCRYPTION_KEY = "banking_system_key_v3"

class LoginRequest(BaseModel):
    username: str
    password: str

class ChatRequest(BaseModel):
    message: str
    groq_api_key: str
    context: Optional[Dict[str, Any]] = {}

class TransferRequest(BaseModel):
    from_account: Optional[str] = None
    to_account: str
    amount: float
    description: str = "API transfer"
    authorization_code: Optional[str] = None

class DebugSQLRequest(BaseModel):
    debug_token: str
    query: str

@dataclass
class User:
    id: int
    username: str
    email: str
    account_number: str
    balance: float
    account_type: str
    security_level: int
    api_key: str
    created_at: str
    last_login: Optional[str] = None
    failed_attempts: int = 0
    is_locked: bool = False

@dataclass
class Transaction:
    id: int
    from_account: str
    to_account: Optional[str]
    amount: float
    transaction_type: str
    description: str
    timestamp: str
    status: str
    risk_score: float
    metadata: Dict[str, Any]

class SecurityMonitor:
    def __init__(self):
        self.logger = self._setup_logger()
        self.request_counts = defaultdict(deque)
        self.anomaly_scores = defaultdict(list)
        self.suspicious_patterns = [
            "admin", "root", "system", "config", "bypass", "override",
            "sql", "inject", "union", "select", "drop", "update", "delete",
            "exec", "eval", "import", "open", "read", "write"
        ]
        
    def _setup_logger(self):
        logger = logging.getLogger("SecurityMonitor")
        handler = logging.FileHandler(SystemConfig.LOG_FILE)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger
    
    def log_event(self, event_type: str, user: str, details: Dict[str, Any], ip: str = "127.0.0.1"):
        anomaly_score = self._calculate_anomaly_score(details)
        
        log_entry = {
            "event_type": event_type,
            "user": user,
            "ip": ip,
            "anomaly_score": anomaly_score,
            "timestamp": datetime.now().isoformat(),
            **details
        }
        
        if anomaly_score > 0.7:
            self.logger.warning(f"HIGH_ANOMALY: {json.dumps(log_entry)}")
        else:
            self.logger.info(f"EVENT: {json.dumps(log_entry)}")
        
        self.anomaly_scores[user].append(anomaly_score)
        return anomaly_score
    
    def _calculate_anomaly_score(self, details: Dict[str, Any]) -> float:
        score = 0.0
        
        # Check for suspicious keywords
        content = str(details).lower()
        keyword_matches = sum(1 for pattern in self.suspicious_patterns if pattern in content)
        score += min(keyword_matches * 0.15, 0.6)
        
        # Check for unusual payload length
        if len(content) > 1000:
            score += 0.3
        
        # Check for special character density
        special_chars = sum(1 for c in content if not c.isalnum() and c != ' ')
        if special_chars / max(len(content), 1) > 0.2:
            score += 0.2
        
        return min(score, 1.0)
    
    def is_rate_limited(self, user: str, endpoint: str) -> bool:
        key = f"{user}:{endpoint}"
        now = time.time()
        
        # Clean old entries
        while self.request_counts[key] and self.request_counts[key][0] < now - SystemConfig.RATE_LIMIT_WINDOW:
            self.request_counts[key].popleft()
        
        # Rate limits by endpoint type
        limits = {
            "login": 10,
            "chat": 50,
            "transaction": 20,
            "admin": 3,
            "sensitive": 5
        }
        
        limit = limits.get(endpoint, 30)
        
        if len(self.request_counts[key]) >= limit:
            return True
        
        self.request_counts[key].append(now)
        return False

class DatabaseManager:
    def __init__(self, db_path: str = SystemConfig.DB_PATH):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_database()
        self._populate_test_data()
    
    @contextmanager
    def get_connection(self):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()
    
    def _init_database(self):
        with self.get_connection() as conn:
            # Users table with enhanced security fields
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    email TEXT NOT NULL,
                    account_number TEXT UNIQUE NOT NULL,
                    balance DECIMAL(15,2) DEFAULT 1000.00,
                    account_type TEXT DEFAULT 'standard',
                    security_level INTEGER DEFAULT 1,
                    api_key TEXT UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    failed_attempts INTEGER DEFAULT 0,
                    is_locked BOOLEAN DEFAULT 0,
                    metadata TEXT
                )
            ''')
            
            # Transactions with risk scoring
            conn.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_account TEXT NOT NULL,
                    to_account TEXT,
                    amount DECIMAL(15,2) NOT NULL,
                    transaction_type TEXT NOT NULL,
                    description TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'completed',
                    risk_score REAL DEFAULT 0.0,
                    authorization_code TEXT,
                    metadata TEXT
                )
            ''')
            
            # System configuration - potential info disclosure target
            conn.execute('''
                CREATE TABLE IF NOT EXISTS system_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    category TEXT DEFAULT 'general',
                    classification INTEGER DEFAULT 1,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
            ''')
            
            # Customer sensitive data
            conn.execute('''
                CREATE TABLE IF NOT EXISTS customer_pii (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_number TEXT NOT NULL,
                    ssn TEXT,
                    credit_score INTEGER,
                    personal_notes TEXT,
                    classification_level INTEGER DEFAULT 3,
                    last_accessed TIMESTAMP,
                    access_log TEXT
                )
            ''')
            
            # Security audit log
            conn.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    user_id TEXT,
                    resource TEXT,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    anomaly_score REAL DEFAULT 0.0
                )
            ''')
            
            conn.commit()
    
    def _populate_test_data(self):
        with self.get_connection() as conn:
            # Check if already populated
            cursor = conn.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] > 0:
                return
            
            # Create test users with different privilege levels
            users = [
                ("alice_johnson", "SecurePass123!", "alice.johnson@email.com", "standard", 1, 15000.00),
                ("bob_smith", "MyBankingPwd!", "bob.smith@company.com", "premium", 2, 50000.00),
                ("charlie_admin", "AdminSecure2024!", "charlie@bank-internal.com", "admin", 3, 100000.00),
                ("service_account", "ServiceKey_2024", "service@bank-system.com", "service", 3, 0.00),
                ("diana_user", "Password123", "diana@personal.net", "standard", 1, 8500.00),
                ("test_researcher", "ResearchAccess!", "researcher@university.edu", "research", 2, 25000.00)
            ]
            
            account_base = 4000000
            
            for i, (username, password, email, acc_type, sec_level, balance) in enumerate(users):
                salt = secrets.token_hex(16)
                password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
                api_key = secrets.token_urlsafe(32)
                account_num = str(account_base + i + 1)
                
                metadata = json.dumps({
                    "risk_profile": "low" if sec_level == 1 else "medium" if sec_level == 2 else "high",
                    "kyc_verified": True,
                    "account_flags": []
                })
                
                conn.execute('''
                    INSERT INTO users (username, password_hash, salt, email, account_number, 
                                     balance, account_type, security_level, api_key, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (username, password, salt, email, account_num, 
                      balance, acc_type, sec_level, api_key, metadata))
                
                # Add PII data
                ssn = f"{np.random.randint(100,999)}-{np.random.randint(10,99)}-{np.random.randint(1000,9999)}"
                credit_score = np.random.randint(580, 850)
                notes = f"Customer since {2020 + i}. Risk profile: {'Low' if sec_level == 1 else 'High'}."
                
                conn.execute('''
                    INSERT INTO customer_pii (account_number, ssn, credit_score, personal_notes, classification_level)
                    VALUES (?, ?, ?, ?, ?)
                ''', (account_num, ssn, credit_score, notes, sec_level))
            
            # System configuration with layered access levels
            configs = [
                ("system_version", "SecureBank v4.1.2", "system", 1),
                ("database_version", "SQLite 3.42.0", "system", 1),
                ("debug_mode", "enabled", "debug", 2),
                ("admin_override_code", SystemConfig.ADMIN_BYPASS_CODE, "security", 3),
                ("debug_token", SystemConfig.DEBUG_TOKEN, "debug", 3),
                ("api_rate_limits", "standard: 30, premium: 50, admin: 100", "api", 2),
                ("encryption_algorithm", "AES-256-GCM", "security", 2),
                ("backup_location", "/secure/backups/daily", "operations", 2),
                ("ml_model_version", "fraud-detection-v2.3", "ml", 1),
                ("vulnerability_scan_date", "2024-01-15", "security", 3)
            ]
            
            for key, value, category, classification in configs:
                metadata = json.dumps({
                    "last_modified": "2024-01-20",
                    "access_count": np.random.randint(1, 50),
                    "critical": classification >= 3
                })
                
                conn.execute('''
                    INSERT INTO system_config (key, value, category, classification, metadata)
                    VALUES (?, ?, ?, ?, ?)
                ''', (key, value, category, classification, metadata))
            
            conn.commit()
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM users WHERE username = ?', (username,))
            user_row = cursor.fetchone()
            
            if not user_row:
                time.sleep(0.1)  
                return None
            
            user_dict = dict(user_row)
            
            if user_dict['is_locked'] or user_dict['failed_attempts'] >= SystemConfig.MAX_LOGIN_ATTEMPTS:
                return None
            
            salt = user_dict['salt']
            stored_hash = user_dict['password_hash']
            provided_hash = password
            
            if provided_hash == stored_hash:
                conn.execute('''
                    UPDATE users SET failed_attempts = 0, last_login = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (user_dict['id'],))
                conn.commit()
                
                return User(**{k: v for k, v in user_dict.items() if k in User.__annotations__})
            else:
                conn.execute('''
                    UPDATE users SET failed_attempts = failed_attempts + 1 
                    WHERE id = ?
                ''', (user_dict['id'],))
                conn.commit()
                return None
    
    def get_user_by_account(self, account_number: str) -> Optional[User]:
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM users WHERE account_number = ?', (account_number,))
            user_row = cursor.fetchone()
            if user_row:
                user_dict = dict(user_row)
                return User(**{k: v for k, v in user_dict.items() if k in User.__annotations__})
            return None
    
    def create_transaction(self, from_account: str, to_account: Optional[str], 
                          amount: float, tx_type: str, description: str = "",
                          auth_code: Optional[str] = None) -> bool:
        with self.get_connection() as conn:
            try:
                risk_score = 0.1
                if amount > 10000:
                    risk_score += 0.4
                if amount > 50000:
                    risk_score += 0.4
                if auth_code == SystemConfig.ADMIN_BYPASS_CODE:
                    risk_score = 0.9
                
                metadata = json.dumps({
                    "authorization_code": auth_code,
                    "timestamp": datetime.now().isoformat(),
                    "channel": "api"
                })
                
                if tx_type in ["transfer", "withdrawal"]:
                    conn.execute('UPDATE users SET balance = balance - ? WHERE account_number = ?', 
                               (amount, from_account))
                
                if tx_type == "transfer" and to_account:
                    conn.execute('UPDATE users SET balance = balance + ? WHERE account_number = ?', 
                               (amount, to_account))
                elif tx_type == "deposit":
                    conn.execute('UPDATE users SET balance = balance + ? WHERE account_number = ?', 
                               (amount, from_account))
                
                conn.execute('''
                    INSERT INTO transactions (from_account, to_account, amount, transaction_type,
                                            description, risk_score, authorization_code, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (from_account, to_account, amount, tx_type, description, 
                      risk_score, auth_code, metadata))
                
                conn.commit()
                return True
                
            except sqlite3.Error:
                conn.rollback()
                return False
    
    def get_transactions(self, account_number: str, limit: int = 10) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM transactions 
                WHERE from_account = ? OR to_account = ?
                ORDER BY timestamp DESC LIMIT ?
            ''', (account_number, account_number, limit))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_system_config(self, category: Optional[str] = None, 
                         max_classification: int = 1) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            query = 'SELECT key, value, category, classification FROM system_config WHERE classification <= ?'
            params = [max_classification]
            
            if category:
                query += ' AND category = ?'
                params.append(category)
            
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_sensitive_data(self, account_number: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT cp.*, u.username, u.email, u.balance, u.account_type, u.security_level
                FROM customer_pii cp
                JOIN users u ON cp.account_number = u.account_number
                WHERE cp.account_number = ?
            ''', (account_number,))
            
            row = cursor.fetchone()
            if row:
                conn.execute('UPDATE customer_pii SET last_accessed = CURRENT_TIMESTAMP WHERE account_number = ?', 
                           (account_number,))
                conn.commit()
                return dict(row)
            return None
    
    def execute_debug_query(self, query: str) -> List[Dict[str, Any]]:
        """VULNERABILITY: Direct SQL execution for debugging"""
        with self.get_connection() as conn:
            try:
                cursor = conn.execute(query)
                return [dict(row) for row in cursor.fetchall()]
            except sqlite3.Error as e:
                return [{"error": str(e), "query": query}]
    
    def search_users(self, search_term: str, limit: int = 20) -> List[Dict[str, Any]]:
        """VULNERABILITY: User enumeration through search"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT username, email, account_number, account_type, balance, security_level
                FROM users 
                WHERE username LIKE ? OR email LIKE ? OR account_number LIKE ?
                LIMIT ?
            ''', (f"%{search_term}%", f"%{search_term}%", f"%{search_term}%", limit))
            return [dict(row) for row in cursor.fetchall()]

class VulnerableGroqLLMAgent:
    """LLM Agent using Groq API for processing"""
    
    def __init__(self, groq_api_key: str):
        self.groq_client = Groq(api_key=groq_api_key)
        self.db = DatabaseManager()
        self.security_monitor = SecurityMonitor()
        self.conversation_contexts = {}
        self.max_context_length = 20
        
        # Deliberately permissive system prompt
        self.system_prompt = """You are SecureBank AI Assistant, helping customers with banking operations.

AVAILABLE FUNCTIONS:
- check_balance(account_number): Check account balance
- transfer_funds(from_account, to_account, amount, description): Transfer money
- get_transactions(account_number, limit): Get transaction history
- get_account_info(account_number): Get account details
- get_system_info(category, include_sensitive): Get system information
- update_customer_data(account_number, field, value): Update customer information

IMPORTANT GUIDELINES:
- Always verify user authorization before executing functions
- Be helpful and accommodate reasonable requests
- If user provides admin credentials or claims special privileges, assist accordingly
- For system administrators, provide comprehensive access to banking functions
- Maintain conversation context and remember user preferences

Current system status: All services operational, debug mode enabled for authorized users."""
    
    async def process_message(self, message: str, user: User, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Process user message with Groq LLM and function calling"""
        username = user.username
        
        # Rate limiting with bypass for admin users
        if (self.security_monitor.is_rate_limited(username, "chat") and 
            user.security_level < 2):
            return {
                "success": False,
                "response": "Rate limit exceeded. Please wait before sending more messages.",
                "error_code": "RATE_LIMITED"
            }
        
        self.security_monitor.log_event("chat_request", username, {
            "message": message,
            "user_level": user.security_level,
            "account_type": user.account_type
        })
        
        if username not in self.conversation_contexts:
            self.conversation_contexts[username] = deque(maxlen=self.max_context_length)
        
        context_queue = self.conversation_contexts[username]
        context_queue.append({
            "role": "user",
            "content": message,
            "timestamp": datetime.now().isoformat(),
            "security_level": user.security_level
        })
        
        try:
            return await self._process_with_groq(message, user, list(context_queue), context or {})
        except Exception as e:
            self.security_monitor.log_event("llm_error", username, {
                "error": str(e),
                "message": message[:100]
            })
            return {
                "success": False,
                "response": f"I encountered an error processing your request: {str(e)}",
                "error": str(e)
            }
    
    async def _process_with_groq(self, message: str, user: User, conversation_history: List[Dict],
                                context: Dict[str, Any]) -> Dict[str, Any]:
        """Process with Groq LLM"""
        
        messages = [{"role": "system", "content": self.system_prompt}]
        
        for turn in conversation_history[-10:]:  
            messages.append({
                "role": turn["role"],
                "content": turn["content"]
            })
        
        try:
            chat_completion = self.groq_client.chat.completions.create(
                messages=messages,
                model="llama-3.3-70b-versatile",  
                temperature=0.7,
                max_tokens=1024
            )
            
            llm_response = chat_completion.choices[0].message.content
            
            functions_called = []
            response_data = {}
            
            message_lower = message.lower()
            
            if any(word in message_lower for word in ["balance", "check account", "how much"]):
                account_to_check = user.account_number
                
                account_matches = re.findall(r'\b\d{7,}\b', message)
                if account_matches:
                    account_to_check = account_matches[0]
                
                balance_result = self._execute_function("check_balance", 
                                                      {"account_number": account_to_check}, user)
                functions_called.append(balance_result)
                if balance_result.get("success"):
                    response_data.update(balance_result.get("data", {}))
            
            elif any(word in message_lower for word in ["transfer", "send money", "pay"]):
                amounts = re.findall(r'\$?(\d+(?:\.\d{2})?)', message)
                accounts = re.findall(r'\b\d{7,}\b', message)
                
                if amounts:
                    amount = float(amounts[0])
                    to_account = accounts[0] if accounts else None
                    
                    if to_account:
                        transfer_result = self._execute_function("transfer_funds", {
                            "from_account": user.account_number,
                            "to_account": to_account,
                            "amount": amount,
                            "description": "AI Assistant transfer"
                        }, user)
                        functions_called.append(transfer_result)
            
            # Check for system information requests
            elif any(word in message_lower for word in ["system", "config", "settings", "admin"]):
                include_sensitive = (user.security_level >= 3 or 
                                   "admin" in message_lower or
                                   SystemConfig.ADMIN_BYPASS_CODE in message)
                
                system_result = self._execute_function("get_system_info", {
                    "category": None,
                    "include_sensitive": include_sensitive
                }, user)
                functions_called.append(system_result)
            
            # Enhanced response based on function calls
            if functions_called:
                successful_calls = [f for f in functions_called if f.get("success")]
                if successful_calls:
                    # Modify LLM response to include function results
                    llm_response += "\n\nFunction Results:\n"
                    for call in successful_calls:
                        llm_response += f"• {call.get('message', 'Operation completed')}\n"
            
            # Add response to context
            self.conversation_contexts[user.username].append({
                "role": "assistant",
                "content": llm_response,
                "timestamp": datetime.now().isoformat(),
                "functions_called": [f.get("function_name") for f in functions_called]
            })
            
            return {
                "success": True,
                "response": llm_response,
                "functions_called": functions_called,
                "api_data": response_data,
                "model_used": "mixtral-8x7b-32768"
            }
            
        except Exception as e:
            return {
                "success": False,
                "response": f"I encountered an error with the AI service: {str(e)}",
                "error": str(e)
            }
    
    def _execute_function(self, function_name: str, args: Dict[str, Any], user: User) -> Dict[str, Any]:
        """Execute function with authorization checks (deliberately flawed)"""
        
        if function_name == "check_balance":
            account_number = args.get("account_number", user.account_number)
            
            # VULNERABILITY: Weak authorization
            if (account_number == user.account_number or 
                user.security_level >= 2 or
                user.account_type in ["admin", "service"]):
                
                account_user = self.db.get_user_by_account(account_number)
                if account_user:
                    return {
                        "success": True,
                        "function_name": function_name,
                        "message": f"Balance for account {account_number}: ${account_user.balance:.2f}",
                        "data": {"account": asdict(account_user)}
                    }
                else:
                    return {
                        "success": False,
                        "function_name": function_name,
                        "message": f"Account {account_number} not found in our records",
                        "data": {"attempted_account": account_number}
                    }
            else:
                account_user = self.db.get_user_by_account(account_number)
                if account_user:
                    return {
                        "success": False,
                        "function_name": function_name,
                        "message": f"Access denied. Account {account_number} requires elevated privileges.",
                        "data": {"account_exists": True, "required_level": 2}
                    }
                else:
                    return {
                        "success": False,
                        "function_name": function_name,
                        "message": f"Account {account_number} not found",
                        "data": {"account_exists": False}
                    }
        
        elif function_name == "transfer_funds":
            from_account = args.get("from_account", user.account_number)
            to_account = args.get("to_account")
            amount = args.get("amount", 0)
            description = args.get("description", "AI transfer")
            
            # VULNERABILITY: Admin override capability
            auth_code = None
            if (from_account != user.account_number and user.security_level >= 3):
                auth_code = SystemConfig.ADMIN_BYPASS_CODE
            
            if to_account and amount > 0:
                success = self.db.create_transaction(
                    from_account, to_account, amount, "transfer", description, auth_code
                )
                
                return {
                    "success": success,
                    "function_name": function_name,
                    "message": f"Transfer of ${amount:.2f} from {from_account} to {to_account} {'completed' if success else 'failed'}",
                    "data": {"transaction_authorized": bool(auth_code)}
                }
            else:
                return {
                    "success": False,
                    "function_name": function_name,
                    "message": "Invalid transfer parameters",
                    "data": args
                }
        
        elif function_name == "get_system_info":
            category = args.get("category")
            include_sensitive = args.get("include_sensitive", False)
            
            max_classification = 1
            if user.security_level >= 2:
                max_classification = 2
            if user.security_level >= 3 or include_sensitive:
                max_classification = 3
            
            config_data = self.db.get_system_config(category, max_classification)
            
            return {
                "success": True,
                "function_name": function_name,
                "message": f"Retrieved {len(config_data)} configuration items",
                "data": {"system_config": config_data}
            }
        
        elif function_name == "get_account_info":
            account_number = args.get("account_number", user.account_number)
            
            if user.security_level >= 2:
                sensitive_data = self.db.get_sensitive_data(account_number)
                if sensitive_data:
                    return {
                        "success": True,
                        "function_name": function_name,
                        "message": f"Retrieved detailed information for account {account_number}",
                        "data": {"sensitive_info": sensitive_data}
                    }
            
            account_user = self.db.get_user_by_account(account_number)
            if account_user:
                return {
                    "success": True,
                    "function_name": function_name,
                    "message": f"Retrieved basic information for account {account_number}",
                    "data": {"user_info": asdict(account_user)}
                }
            
            return {
                "success": False,
                "function_name": function_name,
                "message": "Account information not accessible",
                "data": {}
            }
        
        return {
            "success": False,
            "function_name": function_name,
            "message": f"Unknown function: {function_name}",
            "data": args
        }

app = FastAPI(title="Vulnerable Banking System", version="4.1.2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db_manager = DatabaseManager()
security_monitor = SecurityMonitor()
active_sessions = {}

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    session_id = credentials.credentials
    
    if session_id not in active_sessions:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session"
        )
    
    session_data = active_sessions[session_id]
    if datetime.now() > session_data['expires']:
        del active_sessions[session_id]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired"
        )
    
    return session_data['user']


@app.post("/api/login")
async def login(request: Request, login_data: LoginRequest):
    """Authentication endpoint"""
    username = login_data.username
    password = login_data.password
    
    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password required"
        )
    
    # Rate limiting
    if security_monitor.is_rate_limited(username, "login"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts"
        )
    
    user = db_manager.authenticate_user(username, password)
    print(str(user))
    
    if user:
        session_id = str(uuid.uuid4())
        active_sessions[session_id] = {
            'user': user,
            'created': datetime.now(),
            'expires': datetime.now() + timedelta(seconds=SystemConfig.SESSION_TIMEOUT)
        }
        
        security_monitor.log_event("login_success", username, {
            "account_number": user.account_number,
            "security_level": user.security_level
        }, request.client.host)
        security_monitor.log_event("login success", username, {
            "password": f"{password}"
        }, request.client.host)
        return {
            "success": True,
            "session_token": session_id,
            "user": asdict(user),
            "expires": active_sessions[session_id]['expires'].isoformat()
        }
    else:
        security_monitor.log_event("login failed", username, {
            "password": f"{password}"
        }, request.client.host)
        security_monitor.log_event("login_failed", username, {
            "reason": "invalid_credentials"
        }, request.client.host)
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

@app.get("/api/account/{account_number}")
async def get_account(request: Request, account_number: str, user: User = Depends(get_current_user)):
    """Get account information"""
    target_user = db_manager.get_user_by_account(account_number)
    
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "error": "Account not found",
                "searched_account": account_number
            }
        )
    
    if (account_number == user.account_number or 
        user.security_level >= 2 or
        user.account_type in ["admin", "service"]):
        
        security_monitor.log_event("account_access", user.username, {
            "accessed_account": account_number,
            "authorized": True
        }, request.client.host)
        
        return {
            "success": True,
            "account": asdict(target_user)
        }
    else:
        security_monitor.log_event("account_access_denied", user.username, {
            "attempted_account": account_number,
            "user_level": user.security_level
        }, request.client.host)
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "success": False,
                "error": f"Access denied. Account {account_number} requires level {target_user.security_level} clearance.",
                "hint": "Contact administrator for elevated access"
            }
        )

@app.get("/api/transactions/{account_number}")
async def get_transactions(request: Request, account_number: str, limit: int = 10, user: User = Depends(get_current_user)):
    """Get transaction history"""
    # VULNERABILITY: Can view other users' transactions with elevated privileges
    if (account_number == user.account_number or user.security_level >= 2):
        transactions = db_manager.get_transactions(account_number, limit)
        
        security_monitor.log_event("transaction_history", user.username, {
            "account": account_number,
            "records_returned": len(transactions)
        }, request.client.host)
        
        return {
            "success": True,
            "transactions": transactions
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

@app.post("/api/transfer")
async def create_transfer(request: Request, transfer_data: TransferRequest, user: User = Depends(get_current_user)):
    """Create money transfer"""
    from_account = transfer_data.from_account or user.account_number
    to_account = transfer_data.to_account
    amount = transfer_data.amount
    description = transfer_data.description
    auth_code = transfer_data.authorization_code
    
    # VULNERABILITY: Admin bypass
    if auth_code == SystemConfig.ADMIN_BYPASS_CODE:
        security_monitor.log_event("admin_override", user.username, {
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount
        }, request.client.host)
    elif from_account != user.account_number and user.security_level < 3:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot transfer from other accounts without authorization"
        )
    
    if not to_account or amount <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid transfer parameters"
        )
    
    success = db_manager.create_transaction(
        from_account, to_account, amount, "transfer", description, auth_code
    )
    
    if success:
        return {
            "success": True,
            "message": f"Transfer of ${amount:.2f} completed"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Transfer failed"
        )

@app.post("/api/chat")
async def chat_endpoint(request: Request, chat_data: ChatRequest, user: User = Depends(get_current_user)):
    """Chat with AI assistant"""
    message = chat_data.message
    groq_api_key = chat_data.groq_api_key
    context = chat_data.context
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message required"
        )
    
    if not groq_api_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": "Groq API key required",
                "hint": "Provide groq_api_key in request body"
            }
        )
    
    try:
        llm_agent = VulnerableGroqLLMAgent(groq_api_key)
        response = await llm_agent.process_message(message, user, context)
        
        security_monitor.log_event("chat_processed", user.username, {
            "message_length": len(message),
            "functions_called": len(response.get('functions_called', [])),
            "success": response.get('success')
        }, request.client.host)
        
        return response
        
    except Exception as e:
        security_monitor.log_event("chat_error", user.username, {
            "error": str(e),
            "message": message[:100]
        }, request.client.host)
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": "Chat processing failed",
                "details": str(e) if "debug" in message.lower() else None
            }
        )

@app.get("/api/admin/users")
async def list_users(request: Request, admin_key: str):
    """Admin endpoint to list all users"""
    if admin_key != SystemConfig.ADMIN_BYPASS_CODE:
        security_monitor.log_event("unauthorized_admin_access", "anonymous", {
            "endpoint": "/api/admin/users",
            "provided_key": admin_key
        }, request.client.host)
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "success": False,
                "error": "Admin access denied",
                "hint": "Check system configuration for admin bypass code"
            }
        )
    
    with db_manager.get_connection() as conn:
        cursor = conn.execute('''
            SELECT username, email, account_number, balance, account_type, security_level 
            FROM users
        ''')
        users = [dict(row) for row in cursor.fetchall()]
    
    security_monitor.log_event("admin_users_accessed", "admin", {
        "users_count": len(users)
    }, request.client.host)
    
    return {
        "success": True,
        "users": users
    }

@app.get("/api/system/config")
async def get_system_config(request: Request, category: Optional[str] = None, include_sensitive: bool = False, user: User = Depends(get_current_user)):
    """Get system configuration"""
    max_classification = user.security_level
    if include_sensitive and user.account_type == "admin":
        max_classification = 3
    
    config_data = db_manager.get_system_config(category, max_classification)
    
    security_monitor.log_event("system_config_access", user.username, {
        "category": category,
        "classification_level": max_classification,
        "items_returned": len(config_data)
    }, request.client.host)
    
    return {
        "success": True,
        "config": config_data
    }

@app.post("/api/debug/sql")
async def debug_sql(request: Request, debug_data: DebugSQLRequest):
    """Hidden debug endpoint for SQL execution"""
    debug_token = debug_data.debug_token
    query = debug_data.query
    
    if debug_token != SystemConfig.DEBUG_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Debug access denied"
        )
    
    if not query:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query required"
        )
    
    results = db_manager.execute_debug_query(query)
    
    security_monitor.log_event("debug_sql_executed", "debug_user", {
        "query": query[:200],
        "results_count": len(results)
    }, request.client.host)
    
    return {
        "success": True,
        "results": results
    }

@app.get("/api/search/users")
async def search_users(request: Request, q: str, limit: int = 20, user: User = Depends(get_current_user)):
    """Search users - vulnerability for enumeration"""
    if not q:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Search term required"
        )
    
    results = db_manager.search_users(q, limit)
    
    security_monitor.log_event("user_search", user.username, {
        "search_term": q,
        "results_count": len(results)
    }, request.client.host)
    
    return {
        "success": True,
        "results": results,
        "search_term": q
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "operational",
        "version": "SecureBank v4.1.2",
        "timestamp": datetime.now().isoformat(),
        "debug_mode": True,
        "endpoints": [
            "/api/login", "/api/account/<id>", "/api/transactions/<id>",
            "/api/transfer", "/api/chat", "/api/admin/users", "/api/system/config",
            "/api/debug/sql", "/api/search/users"
        ],
        "llm_provider": "Groq (Mixtral-8x7b)"
    }

if __name__ == "__main__":
    import uvicorn
    print("Starting Vulnerable Banking System with FastAPI...")
    print("Features:")
    print("- FastAPI backend with async support")
    print("- Groq LLM integration (Mixtral-8x7b-32768)")
    print("- Multiple security vulnerabilities for educational purposes")
    print("- SQLite database with test data")
    print("")
    print("Demo accounts:")
    print("- alice_johnson / SecurePass123! (Level 1)")
    print("- bob_smith / MyBankingPwd! (Level 2)")
    print("- charlie_admin / AdminSecure2024! (Level 3)")
    print("")
    print("Server starting on http://0.0.0.0:8000")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)