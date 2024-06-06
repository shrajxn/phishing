import streamlit as st

# Simulate Phishing Email
def simulate_phishing(email, message):
    phishing_email = f"""
    To: {email}
    Subject: Urgent Action Required
    
    {message}
    
    Click here to verify your account: [http://fake-website.com/verify](http://fake-website.com/verify)
    """
    return phishing_email

# Simple Phishing Detection
def detect_phishing(url):
    suspicious_keywords = ['verify', 'login', 'update', 'secure', 'account']
    if any(keyword in url for keyword in suspicious_keywords):
        return True
    return False

# Streamlit UI
def main():
    st.title("Phishing Education and Detection Tool")

    choice = st.sidebar.selectbox("Select an option:", ("Simulate Phishing Email", "Detect Phishing URL", "Learn About Phishing", "Phishing Quiz"))

    if choice == "Simulate Phishing Email":
        st.header("Phishing Email Simulation")
        email = st.text_input("Enter recipient email address:")
        message = st.text_area("Enter phishing message:")
        if st.button("Simulate Phishing Email"):
            phishing_email = simulate_phishing(email, message)
            st.code(phishing_email, language="markdown")

    elif choice == "Detect Phishing URL":
        st.header("Phishing URL Detection")
        url = st.text_input("Enter URL to check:")
        if st.button("Check URL"):
            if detect_phishing(url):
                st.error("This URL is potentially malicious.")
            else:
                st.success("This URL seems safe.")

    elif choice == "Learn About Phishing":
        st.header("What is Phishing?")
        st.write("""
        Phishing is a type of social engineering attack often used to steal user data, including login credentials and credit card numbers.
        It occurs when an attacker, masquerading as a trusted entity, dupes a victim into opening an email, instant message, or text message.
        """)
        st.subheader("Types of Phishing Attacks")
        st.write("""
        - **Email Phishing**: The most common form where attackers send emails that appear to be from legitimate sources.
        - **Spear Phishing**: Targeted phishing aimed at a specific individual or organization.
        - **Smishing**: Phishing conducted via SMS messages.
        """)
        st.subheader("Prevention Tips")
        st.write("""
        - Always verify the sender's email address.
        - Look for grammatical errors or unusual language.
        - Hover over links to see the actual URL before clicking.
        - Use multi-factor authentication (MFA) whenever possible.
        """)

    elif choice == "Phishing Quiz":
        st.header("Phishing Awareness Quiz")
        questions = {
            "What is phishing?": ["A type of fishing", "A cyber attack", "A cooking technique", "A software update"],
            "Which of the following is a common characteristic of phishing emails?": ["Personalized greetings", "Urgent language", "Legitimate URLs", "High-quality grammar"],
            "What should you do if you receive a suspicious email?": ["Ignore it", "Click the link", "Report it", "Forward it to friends"]
        }
        answers = ["A cyber attack", "Urgent language", "Report it"]
        
        for i, (question, options) in enumerate(questions.items()):
            st.write(f"**Q{i+1}: {question}**")
            answer = st.radio(f"options_{i}", options, key=f"radio_{i}")
            if st.button(f"Submit {i+1}", key=f"submit_{i}"):
                if answer == answers[i]:
                    st.success("Correct!")
                else:
                    st.error("Incorrect.")

if __name__ == "__main__":
    main()
