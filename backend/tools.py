from __future__ import annotations

from langchain_core.tools import tool

from backend.repository import LoginRepository


def build_tools(repository: LoginRepository, session_id: int):
    @tool
    def fetch_customer_profile(identifier: str) -> str:
        """Look up a customer profile by username, customer ID, or email."""
        return str(repository.get_user_snapshot(identifier))

    @tool
    def explain_account_status(identifier: str) -> str:
        """Describe the current account status, password-reset flag, and failed-attempt summary."""
        return repository.explain_account_status(identifier)

    @tool
    def generate_otp(identifier: str, purpose: str, device_id: str = "", location: str = "") -> str:
        """Generate an OTP for password reset, unlock account, suspicious activity review, or new device login."""
        result = repository.create_otp(identifier, purpose, session_id, device_id or None, location or None)
        if result.get("ok"):
            return (
                f"OTP generated successfully. "
                f"Phone hint: {result.get('message')} "
                f"It is valid for 5 minutes. "
                f"For this demo project, retrieve the code from the OTP utility page instead of showing it in chat."
            )
        return str(result)

    @tool
    def verify_customer_otp(identifier: str, otp_code: str) -> str:
        """Verify the latest pending OTP for a customer."""
        return str(repository.verify_otp(identifier, otp_code))

    @tool
    def get_latest_session_otp_status() -> str:
        """Get the latest OTP generated in this chat session, including purpose, status, and phone hint."""
        return str(repository.get_latest_session_otp(session_id))

    @tool
    def verify_latest_session_otp(otp_code: str) -> str:
        """Verify the most recent OTP generated in this chat session using the 6-digit code."""
        return str(repository.verify_latest_session_otp(session_id, otp_code))

    @tool
    def get_current_workflow_status() -> str:
        """Fetch the current workflow state for this chat session."""
        return str(repository.get_workflow_status(session_id))

    @tool
    def remember_customer_preference(identifier: str, memory_key: str, memory_value: str) -> str:
        """Store a useful customer memory such as preferred channel, trusted device alias, or last issue resolved."""
        return str(repository.remember_customer_detail(identifier, memory_key, memory_value, "agent", session_id))

    @tool
    def fetch_customer_memory(identifier: str) -> str:
        """Retrieve durable customer memory saved from previous support interactions."""
        return str(repository.get_customer_memory(identifier))

    @tool
    def unlock_customer_account(identifier: str) -> str:
        """Unlock a customer's account after successful verification."""
        return str(repository.unlock_account(identifier, session_id))

    @tool
    def reset_customer_password(identifier: str, new_password: str) -> str:
        """Reset a customer's password after successful verification."""
        return str(repository.reset_password(identifier, new_password, session_id))

    @tool
    def approve_customer_device(identifier: str, device_id: str, location: str) -> str:
        """Approve a newly verified device for customer login access."""
        return str(repository.approve_new_device(identifier, device_id, location, session_id))

    @tool
    def review_security_alerts(identifier: str) -> str:
        """Fetch recent security alerts for a customer who reported suspicious activity."""
        return str(repository.get_security_alerts(identifier))

    @tool
    def secure_customer_account(identifier: str) -> str:
        """Place a customer account into restricted mode after suspicious login activity."""
        return str(repository.secure_account(identifier, session_id))

    return [
        fetch_customer_profile,
        explain_account_status,
        generate_otp,
        verify_customer_otp,
        get_latest_session_otp_status,
        verify_latest_session_otp,
        get_current_workflow_status,
        remember_customer_preference,
        fetch_customer_memory,
        unlock_customer_account,
        reset_customer_password,
        approve_customer_device,
        review_security_alerts,
        secure_customer_account,
    ]
