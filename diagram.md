```mermaid
graph TD
    %% Define Styles for Visual Clarity
    classDef frontend fill:#e1f5fe,stroke:#03a9f4,stroke-width:2px;
    classDef backend fill:#e8f5e9,stroke:#4caf50,stroke-width:2px;
    classDef database fill:#fff3e0,stroke:#ff9800,stroke-width:2px;
    classDef auth fill:#fce4ec,stroke:#e91e63,stroke-width:2px;

    %% Client / Frontend Layer
    subgraph ClientLayer ["Client Layer (Frontend)"]
        HTML[HTML / JS UI]:::frontend
        GoogleBtn[Google Auth Button]:::frontend
    end

    %% Deployment / Routing Layer (Render)
    subgraph HostingLayer ["Application Hosting (Render)"]
        PythonServer[Python Web Backend<br> Flask / FastAPI]:::backend
    end

    %% Auth Provider
    subgraph IdentityProvider ["Identity Provider"]
        GoogleOAuth[Google OAuth 2.0 API]:::auth
    end

    %% Database & Auth Services (Supabase)
    subgraph BackendServices ["Backend Services (Supabase)"]
        SupaAuth[Supabase Auth Engine]:::auth
        PostgresDB[(PostgreSQL Database)]:::database
        
        subgraph DatabaseSchema ["Database Tables"]
            UsersTable[users]:::database
            ProjectsTable[projects]:::database
            ThreatsTable[threat_models]:::database
            MitigationsTable[mitigations]:::database
        end
    end

    %% 1. Authentication Flow Pathway
    GoogleBtn -->|1. Triggers Login| GoogleOAuth
    GoogleOAuth -->|2. Returns Identity Token| GoogleBtn
    GoogleBtn -->|3. Hands Token to| SupaAuth
    SupaAuth -->|4. Syncs User Record| UsersTable

    %% 2. Application Data & Logic Flow Pathway
    HTML -->|5. Sends App Requests| PythonServer
    PythonServer -->|6. Validates Session JSON JWT| SupaAuth
    
    %% 3. CRUD Database Operations
    PythonServer -->|7. Queries / Writes Data| PostgresDB
    PostgresDB --> ProjectsTable
    PostgresDB --> ThreatsTable
    PostgresDB --> MitigationsTable

    %% 4. Structural Database Schema Relationships
    UsersTable ---|1 to Many Relationship| ProjectsTable
    ProjectsTable ---|1 to Many Relationship| ThreatsTable
    ThreatsTable ---|1 to Many Relationship| MitigationsTable
