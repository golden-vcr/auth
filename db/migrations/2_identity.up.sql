begin;

create table auth.identity (
    twitch_user_id      text primary key,
    twitch_display_name text not null,
    first_logged_in_at  timestamptz not null,
    last_logged_in_at   timestamptz not null
);

comment on table auth.identity is
    'Details about a user, authenticated via Twitch, who has interacted with the '
    'Golden VCR app at some point.';
comment on column auth.identity.twitch_user_id is
    'Text-formatted integer identifying this user in the Twitch API.';
comment on column auth.identity.twitch_display_name is
    'Last known username by which this user was known, formatted for display.';
comment on column auth.identity.first_logged_in_at is
    'Timestamp when the user first logged in at goldenvcr.com.';
comment on column auth.identity.last_logged_in_at is
    'Timestamp when the user most recently logged in at goldenvcr.com.';

commit;
