# Week 7: Secure Authentication System
Student Name: Sungaralingum Koushigen 
Student ID: M01076167
Course: CST1510 -CW2 -  Multi-Domain Intelligence Platform 

## Project Description
A command-line authentication system implementing secure password hashing
This system allows users to register accounts and log in with proper pass

## Features
- Secure password hashing using bcrypt with automatic salt generation
- User registration with duplicate username prevention
- User login with password verification
- Input validation for usernames and passwords
- File-based user data persistence

## Technical Implementation
- Hashing Algorithm: bcrypt with automatic salting
- Data Storage: Plain text file (`users.txt`) with comma
-separated values
- Password Security: One-way hashing, no plaintext storage
- Validation: Username (3-20 alphanumeric characters), Password (6-50 characters)

## Instructions on how to use application
- User registers his username and his password and confirm it.
- The dashboards cannot be viewed unless logged in.
- The user enters his credentials and logs in the system.
- The Domain Dashboard, Analytics Dashboard, Settings Dashboard and AI Assistant Dashboard can now be accessed.
- In the Domain Dashboard, the user can view the database on all 3 domains and operate on the data such as Create, Read, Update or Delete a record.
- In the Analytics Dashboard, metrics and charts are displayed to see data relationship for all domains.
- In the Settings Dashboard, the user can add a new user, change his role, change his password as well as deleting another user.
- (Note: the user cannot delete his own account).
- In the AI Assistant Dashboard (Gemini), the user can ask a ChatBot to analyse live data based on the 3 domains and the intelligent
- assistant will search for the specific domain and answer.
-  If a domain has no available records, the user is informed. 
- If a question is outside the scope of the live data (e.g., theoretical questions), 
- answers would be general knowledge and the database context is ignored.