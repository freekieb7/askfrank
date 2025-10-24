-- Migration: add users (UP)
-- Created: 2025-08-02 21:13:05
-- Version: 20250802211305

CREATE TABLE tbl_user (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_email_verified BOOLEAN NOT NULL,
    is_bot BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_user_email ON tbl_user (email);
CREATE INDEX idx_user_created_at ON tbl_user (created_at);

CREATE TABLE tbl_session (
    id UUID PRIMARY KEY,
    token TEXT NOT NULL,
    user_id UUID REFERENCES tbl_user(id) ON DELETE CASCADE,
    user_agent TEXT,
    ip_address TEXT,
    data JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (token)
);

CREATE INDEX idx_session_user_id ON tbl_session (user_id);
CREATE INDEX idx_session_expires_at ON tbl_session (expires_at);
CREATE INDEX idx_session_revoked_at ON tbl_session (revoked_at);
CREATE INDEX idx_session_created_at ON tbl_session (created_at);

CREATE TABLE tbl_password_reset (
    id UUID PRIMARY KEY,
    token TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (token),
    UNIQUE (user_id, used_at)
);

CREATE INDEX idx_password_reset_user_id ON tbl_password_reset (user_id);
CREATE INDEX idx_password_reset_expires_at ON tbl_password_reset (expires_at);
CREATE INDEX idx_password_reset_created_at ON tbl_password_reset (created_at);

CREATE TABLE tbl_group (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_group_created_at ON tbl_group (created_at);

CREATE TABLE tbl_group_member (
    id UUID PRIMARY KEY,
    group_id UUID NOT NULL REFERENCES tbl_group(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    role TEXT NOT NULL, -- e.g., 'admin', 'member'
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (group_id, user_id)
);

CREATE INDEX idx_group_member_user_id ON tbl_group_member (user_id);
CREATE INDEX idx_group_member_group_id ON tbl_group_member (group_id);
CREATE INDEX idx_group_member_created_at ON tbl_group_member (created_at);

CREATE TABLE tbl_group_invite (
    id UUID PRIMARY KEY,
    token TEXT NOT NULL,
    group_id UUID NOT NULL REFERENCES tbl_group(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL, -- e.g., 'admin', 'member'
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (token),
    UNIQUE (group_id, email, used_at)
);

CREATE INDEX idx_group_invite_group_id ON tbl_group_invite (group_id);
CREATE INDEX idx_group_invite_email ON tbl_group_invite (email);
CREATE INDEX idx_group_invite_expires_at ON tbl_group_invite (expires_at);
CREATE INDEX idx_group_invite_used_at ON tbl_group_invite (used_at);
CREATE INDEX idx_group_invite_created_at ON tbl_group_invite (created_at);

-- CREATE TABLE tbl_file (
--     id UUID PRIMARY KEY,
--     owner_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
--     parent_id UUID REFERENCES tbl_file(id) ON DELETE CASCADE, -- For folders
--     name TEXT NOT NULL,
--     mime_type TEXT NOT NULL,
--     path TEXT NOT NULL,
--     size_bytes BIGINT NOT NULL,
--     created_at TIMESTAMPTZ NOT NULL,
--     updated_at TIMESTAMPTZ NOT NULL
-- );

-- CREATE INDEX idx_file_parent ON tbl_file (parent_id);
-- CREATE INDEX idx_file_path ON tbl_file (path);
-- CREATE INDEX idx_file_created_at ON tbl_file (created_at);

-- CREATE TABLE tbl_file_shared_with_others (
--     id UUID PRIMARY KEY,
--     file_id UUID NOT NULL REFERENCES tbl_file(id) ON DELETE CASCADE,
--     shared_with_user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
--     permission TEXT NOT NULL, -- e.g., 'read', 'write'
--     created_at TIMESTAMPTZ NOT NULL,
--     updated_at TIMESTAMPTZ NOT NULL,
--     UNIQUE (file_id, shared_with_user_id)
-- );

-- CREATE INDEX idx_file_share_file_id ON tbl_file_share (file_id);
-- CREATE INDEX idx_file_share_user_id ON tbl_file_share (shared_with_user_id);
-- CREATE INDEX idx_file_share_created_at ON tbl_file_share (created_at);

-- CREATE TABLE tbl_file_shared_with_me (
--     id UUID PRIMARY KEY,
--     file_id UUID NOT NULL REFERENCES tbl_file(id) ON DELETE CASCADE,
--     owner_user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
--     created_at TIMESTAMPTZ NOT NULL,
--     updated_at TIMESTAMPTZ NOT NULL,
--     UNIQUE (file_id, owner_user_id)
-- );

-- CREATE TABLE tbl_audit_log_event (
--     id UUID PRIMARY KEY,
--     type TEXT NOT NULL, -- e.g., 'login', 'file_upload', 'file_delete'
--     data JSONB,         -- Additional data related to the event
--     created_at TIMESTAMPTZ NOT NULL
-- );

-- CREATE INDEX idx_audit_log_event_type ON tbl_audit_log_event (type);
-- CREATE INDEX idx_audit_log_event_created_at ON tbl_audit_log_event (created_at);

-- CREATE TABLE tbl_webhook_event (
--     id UUID PRIMARY KEY,
--     type TEXT NOT NULL,  -- e.g., 'file_uploaded', 'file_deleted'
--     payload JSONB NOT NULL,    -- The payload sent to the webhook
--     created_at TIMESTAMPTZ NOT NULL
-- );

-- CREATE INDEX idx_webhook_event_type ON tbl_webhook_event (type);
-- CREATE INDEX idx_webhook_event_created_at ON tbl_webhook_event (created_at);

-- CREATE TABLE tbl_webhook_subscription (
--     id UUID PRIMARY KEY,
--     name TEXT NOT NULL,
--     description TEXT NOT NULL,
--     url TEXT NOT NULL,
--     secret TEXT NOT NULL,      
--     event_types TEXT[] NOT NULL,
--     is_active BOOLEAN NOT NULL,
--     created_at TIMESTAMPTZ NOT NULL,
--     updated_at TIMESTAMPTZ NOT NULL
-- );

-- CREATE INDEX idx_webhook_subscription_event_types ON tbl_webhook_subscription USING GIN (event_types);
-- CREATE INDEX idx_webhook_subscription_is_active ON tbl_webhook_subscription (is_active);
-- CREATE INDEX idx_webhook_subscription_url ON tbl_webhook_subscription (url);
-- CREATE INDEX idx_webhook_subscription_created_at ON tbl_webhook_subscription (created_at);

-- CREATE TABLE tbl_webhook_delivery (
--     id UUID PRIMARY KEY,
--     event_id UUID NOT NULL REFERENCES tbl_webhook_event(id) ON DELETE CASCADE,
--     subscription_id UUID NOT NULL REFERENCES tbl_webhook_subscription(id) ON DELETE CASCADE,
--     status TEXT NOT NULL,
--     retry_count INT NOT NULL,
--     next_attempt_at TIMESTAMPTZ,
--     last_attempt_at TIMESTAMPTZ,
--     last_response_code INT,
--     last_response_body TEXT,
--     created_at TIMESTAMPTZ NOT NULL,
--     updated_at TIMESTAMPTZ NOT NULL
-- );

-- CREATE INDEX idx_webhook_delivery_event_id ON tbl_webhook_delivery (event_id);
-- CREATE INDEX idx_webhook_delivery_subscription_id ON tbl_webhook_delivery (subscription_id);
-- CREATE INDEX idx_webhook_delivery_status ON tbl_webhook_delivery (status);
-- CREATE INDEX idx_webhook_delivery_retry_count ON tbl_webhook_delivery (retry_count);
-- CREATE INDEX idx_webhook_delivery_last_attempt_at ON tbl_webhook_delivery (last_attempt_at);
-- CREATE INDEX idx_webhook_delivery_last_response_code ON tbl_webhook_delivery (last_response_code);
-- CREATE INDEX idx_webhook_delivery_created_at ON tbl_webhook_delivery (created_at);

-- CREATE TABLE tbl_calendar_event (
--     id UUID PRIMARY KEY,
--     created_by UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
--     title TEXT NOT NULL,
--     description TEXT NOT NULL,
--     start_timestamp TIMESTAMPTZ NOT NULL,
--     end_timestamp TIMESTAMPTZ NOT NULL,
--     all_day BOOLEAN NOT NULL,
--     status TEXT NOT NULL, -- e.g., 'tentative', 'confirmed', 'cancelled'
--     location TEXT NOT NULL,
--     meeting_id TEXT, -- e.g., Zoom or Google Meet ID
--     created_at TIMESTAMPTZ NOT NULL,
--     updated_at TIMESTAMPTZ NOT NULL
-- );

-- CREATE INDEX idx_calendar_event_created_by ON tbl_calendar_event (created_by);
-- CREATE INDEX idx_calendar_event_start_timestamp ON tbl_calendar_event (start_timestamp);
-- CREATE INDEX idx_calendar_event_end_timestamp ON tbl_calendar_event (end_timestamp);
-- CREATE INDEX idx_calendar_event_created_at ON tbl_calendar_event (created_at);

-- CREATE TABLE tbl_calendar_event_attendee (
--     id UUID PRIMARY KEY,
--     calendar_event_id UUID NOT NULL REFERENCES tbl_calendar_event(id) ON DELETE CASCADE,
--     user_id UUID REFERENCES tbl_user(id) ON DELETE CASCADE,
--     email TEXT,
--     status TEXT NOT NULL, -- e.g., 'accepted', 'declined', 'tentative'
--     created_at TIMESTAMPTZ NOT NULL,
--     updated_at TIMESTAMPTZ NOT NULL,
--     UNIQUE (calendar_event_id, user_id)
-- );

-- CREATE INDEX idx_calendar_event_attendee_event_id ON tbl_calendar_event_attendee (calendar_event_id);
-- CREATE INDEX idx_calendar_event_attendee_user_id ON tbl_calendar_event_attendee (user_id);
-- CREATE INDEX idx_calendar_event_attendee_created_at ON tbl_calendar_event_attendee (created_at);

-- CREATE TABLE tbl_chat_room (
--     id UUID PRIMARY KEY,
--     -- group_id UUID REFERENCES tbl_group(id) ON DELETE CASCADE,
--     name TEXT NOT NULL,
--     type TEXT NOT NULL, -- e.g., 'private', 'group', 'meeting'
--     created_by UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
--     created_at TIMESTAMPTZ NOT NULL,
--     updated_at TIMESTAMPTZ NOT NULL
-- );

-- CREATE INDEX idx_chat_room_created_by ON tbl_chat_room (created_by);
-- CREATE INDEX idx_chat_room_created_at ON tbl_chat_room (created_at);

-- CREATE TABLE tbl_chat_room_member (
--     id UUID PRIMARY KEY,
--     chat_room_id UUID NOT NULL REFERENCES tbl_chat_room(id) ON DELETE CASCADE,
--     user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
--     role TEXT NOT NULL, -- e.g., 'admin', 'member'
--     created_at TIMESTAMPTZ NOT NULL,
--     updated_at TIMESTAMPTZ NOT NULL,
--     UNIQUE (chat_room_id, user_id)
-- );

-- CREATE INDEX idx_chat_room_member_chat_room_id ON tbl_chat_room_member (chat_room_id);
-- CREATE INDEX idx_chat_room_member_user_id ON tbl_chat_room_member (user_id);
-- CREATE INDEX idx_chat_room_member_created_at ON tbl_chat_room_member (created_at);

-- CREATE TABLE tbl_chat_room_message (
--     id UUID PRIMARY KEY,
--     chat_room_id UUID NOT NULL REFERENCES tbl_chat_room(id) ON DELETE CASCADE,
--     author_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
--     content TEXT NOT NULL,
--     created_at TIMESTAMPTZ NOT NULL,
--     updated_at TIMESTAMPTZ NOT NULL,
--     deleted_at TIMESTAMPTZ
-- );

-- CREATE INDEX idx_chat_room_message_chat_room_id ON tbl_chat_room_message (chat_room_id);
-- CREATE INDEX idx_chat_room_message_author_id ON tbl_chat_room_message (author_id);
-- CREATE INDEX idx_chat_room_message_created_at ON tbl_chat_room_message (created_at);

-- CREATE TABLE tbl_meeting (
--     id UUID PRIMARY KEY,
--     owner_organisation_id UUID NOT NULL REFERENCES tbl_organisation(id) ON DELETE CASCADE,
--     owner_user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
--     chat_room_id UUID NOT NULL REFERENCES tbl_chat_room(id) ON DELETE CASCADE,
--     calendar_event_id UUID REFERENCES tbl_calendar_event(id) ON DELETE SET NULL,
--     title TEXT NOT NULL,
--     description TEXT NOT NULL,
--     created_at TIMESTAMPTZ NOT NULL,
--     updated_at TIMESTAMPTZ NOT NULL
-- );

-- CREATE INDEX idx_meeting_owner_organisation_id ON tbl_meeting (owner_organisation_id);
-- CREATE INDEX idx_meeting_owner_user_id ON tbl_meeting (owner_user_id);
-- CREATE INDEX idx_meeting_chat_room_id ON tbl_meeting (chat_room_id);
-- CREATE INDEX idx_meeting_calendar_event_id ON tbl_meeting (calendar_event_id);
-- CREATE INDEX idx_meeting_created_at ON tbl_meeting (created_at);

-- CREATE TABLE tbl_meeting_participant (
--     id UUID PRIMARY KEY,
--     meeting_id UUID NOT NULL REFERENCES tbl_meeting(id) ON DELETE CASCADE,
--     user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
--     role TEXT NOT NULL, -- e.g., 'host', 'co-host', 'participant'
--     created_at TIMESTAMPTZ NOT NULL,
--     updated_at TIMESTAMPTZ NOT NULL,
--     UNIQUE (meeting_id, user_id)
-- );

-- CREATE INDEX idx_meeting_participant_meeting_id ON tbl_meeting_participant (meeting_id);
-- CREATE INDEX idx_meeting_participant_user_id ON tbl_meeting_participant (user_id);
-- CREATE INDEX idx_meeting_participant_created_at ON tbl_meeting_participant (created_at);

-- CREATE TABLE tbl_notification (
--     id UUID PRIMARY KEY,
--     owner_user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
--     type TEXT NOT NULL,        -- e.g., 'info', 'warning', 'error'
--     title TEXT NOT NULL,
--     message TEXT NOT NULL,
--     is_read BOOLEAN NOT NULL,
--     action_url TEXT NOT NULL,
--     created_at TIMESTAMPTZ NOT NULL,
--     updated_at TIMESTAMPTZ NOT NULL
-- );

-- CREATE INDEX idx_notification_owner_user_id ON tbl_notification (owner_user_id);
-- CREATE INDEX idx_notification_type ON tbl_notification (type);
-- CREATE INDEX idx_notification_is_read ON tbl_notification (is_read);
-- CREATE INDEX idx_notification_created_at ON tbl_notification (created_at);

CREATE TABLE tbl_oauth_client (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    secret TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    is_public BOOLEAN NOT NULL,
    scopes TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_oauth_client_created_at ON tbl_oauth_client (created_at);

CREATE TABLE tbl_oauth_access_token (
    id TEXT PRIMARY KEY,
    token TEXT NOT NULL,
    client_id UUID NOT NULL REFERENCES tbl_oauth_client(id) ON DELETE CASCADE,
    user_id UUID REFERENCES tbl_user(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (token)
);

CREATE INDEX idx_oauth_access_token_client_id ON tbl_oauth_access_token (client_id);
CREATE INDEX idx_oauth_access_token_user_id ON tbl_oauth_access_token (user_id);
CREATE INDEX idx_oauth_access_token_expires_at ON tbl_oauth_access_token (expires_at);
CREATE INDEX idx_oauth_access_token_revoked_at ON tbl_oauth_access_token (revoked_at);
CREATE INDEX idx_oauth_access_token_created_at ON tbl_oauth_access_token (created_at);

CREATE TABLE tbl_oauth_auth_code (
    id TEXT PRIMARY KEY,
    token TEXT NOT NULL,
    client_id UUID NOT NULL REFERENCES tbl_oauth_client(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL,
    code_challenge TEXT,
    code_challenge_method TEXT,
    redirect_uri TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (token)
);

CREATE INDEX idx_oauth_auth_code_client_id ON tbl_oauth_auth_code (client_id);
CREATE INDEX idx_oauth_auth_code_user_id ON tbl_oauth_auth_code (user_id);
CREATE INDEX idx_oauth_auth_code_expires_at ON tbl_oauth_auth_code (expires_at);
CREATE INDEX idx_oauth_auth_code_created_at ON tbl_oauth_auth_code (created_at);

CREATE TABLE tbl_oauth_refresh_token_chain (
    id UUID PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES tbl_oauth_client(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_oauth_refresh_token_chain_client_id ON tbl_oauth_refresh_token_chain (client_id);
CREATE INDEX idx_oauth_refresh_token_chain_user_id ON tbl_oauth_refresh_token_chain (user_id);
CREATE INDEX idx_oauth_refresh_token_chain_created_at ON tbl_oauth_refresh_token_chain (created_at);

CREATE TABLE tbl_oauth_refresh_token (
    id TEXT PRIMARY KEY,
    token TEXT NOT NULL,
    chain_id UUID NOT NULL REFERENCES tbl_oauth_refresh_token_chain(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (token),
    UNIQUE (chain_id, used_at)
);

CREATE INDEX idx_oauth_refresh_token_token ON tbl_oauth_refresh_token (token);
CREATE INDEX idx_oauth_refresh_token_chain_id ON tbl_oauth_refresh_token (chain_id);
CREATE INDEX idx_oauth_refresh_token_expires_at ON tbl_oauth_refresh_token (expires_at);
CREATE INDEX idx_oauth_refresh_token_used_at ON tbl_oauth_refresh_token (used_at);
CREATE INDEX idx_oauth_refresh_token_created_at ON tbl_oauth_refresh_token (created_at);