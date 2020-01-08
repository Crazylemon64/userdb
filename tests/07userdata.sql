-- -*- mode: sql; sql-product: postgres -*-

-- Negative test for `bogus_key_userdata`:
-- check that users with bogus ssh_key userdata cannot be inserted.
create function unit_tests.bogus_key_userdata()
returns test_result as $$
declare message test_result;
begin
    begin
        insert into passwd (name, host, "data") values ('ud0', 'fo0.hashbang.sh',
            '{ "name": "x", "ssh_keys": ["nonsense"], "shell": "/usr/bin/zsh" }'::jsonb);
        return assert.fail('Successfully inserted user.');
    exception
    when check_violation then
        return assert.ok('End of test.');
    end;
end $$ language plpgsql;

-- Negative test for `badformat_key_userdata`:
-- check that users with malformatted ssh_key userdata cannot be inserted. (trailing newline)
create function unit_tests.badformat_key_userdata()
returns test_result as $$
declare message test_result;
begin
    begin
        insert into passwd (name, host, "data") values ('ud1', 'fo0.hashbang.sh',
            '{ "name": "x", "ssh_keys": ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8qufjq00OvIcCP24hUHKGR7Xeay7G7iW1VYaUdJDxQc1d3P+qJWCTXPl2yvseg+BdKUUzFDkXGTHjuxxVbvB/ApsUIvrmFt4vS8FrnyvzVOcG5VJ6U5whXW0c61sOcakqn2jt9rScT5kl8RLpHJ+ddy7BfPso4zm69WXaz5X+6DjzVAO8JISbKxDY0nrs5RuuqTxOGIiiB/ZjN5zD21YLIW+fKUiSUd+gMOE8nBfH1rUz41iYSSO0ow8m33nsMwDw34H/OG6NGT2RbD1A3EJa6urGl4AtyIep8QquJzBd1QV+zj6FI7EM/9at9Rj/4F+IW3SYA1Ly5sG+QFv2Wfz7Z//VS1tG4naEHv1DJp0mBaslGAEOwYLRMYluu40O5/VmrWonjfeuouAXC89AVkG6f9PODgzFf3oDvsrO0lZd3523jYQYeCVer+prmp7Z/QJfAuunTXVQ7qsr6UKp+JxjKf5rjB/YVQPilcgDefaGMWdvvttUunyvAT4UBojOdpU= usercomment\n"], "shell": "/usr/bin/zsh" }'::jsonb);
        return assert.fail('Successfully inserted user.');
    exception
    when check_violation then
        return assert.ok('End of test.');
    end;
end $$ language plpgsql;

-- Positive test for `rsa_key_userdata`:
-- check that users with valid rsa ssh_key userdata can be inserted.
create function unit_tests.rsa_key_userdata()
returns test_result as $$
declare message test_result;
begin
    begin
        insert into passwd (name, host, "data") values ('ud2', 'fo0.hashbang.sh',
            '{ "name": "x", "ssh_keys": ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8qufjq00OvIcCP24hUHKGR7Xeay7G7iW1VYaUdJDxQc1d3P+qJWCTXPl2yvseg+BdKUUzFDkXGTHjuxxVbvB/ApsUIvrmFt4vS8FrnyvzVOcG5VJ6U5whXW0c61sOcakqn2jt9rScT5kl8RLpHJ+ddy7BfPso4zm69WXaz5X+6DjzVAO8JISbKxDY0nrs5RuuqTxOGIiiB/ZjN5zD21YLIW+fKUiSUd+gMOE8nBfH1rUz41iYSSO0ow8m33nsMwDw34H/OG6NGT2RbD1A3EJa6urGl4AtyIep8QquJzBd1QV+zj6FI7EM/9at9Rj/4F+IW3SYA1Ly5sG+QFv2Wfz7Z//VS1tG4naEHv1DJp0mBaslGAEOwYLRMYluu40O5/VmrWonjfeuouAXC89AVkG6f9PODgzFf3oDvsrO0lZd3523jYQYeCVer+prmp7Z/QJfAuunTXVQ7qsr6UKp+JxjKf5rjB/YVQPilcgDefaGMWdvvttUunyvAT4UBojOdpU= usercomment"], "shell": "/usr/bin/zsh" }'::jsonb);
        return assert.ok('End of test.');
    exception
    when check_violation then
        return assert.fail('Unable to insert user.');
    end;
end $$ language plpgsql;

-- Positive test for `dsa_key_userdata`:
-- check that users with valid dsa ssh_key userdata can be inserted.
create function unit_tests.dsa_key_userdata()
returns test_result as $$
declare message test_result;
begin
    begin
        insert into passwd (name, host, "data") values ('ud3', 'fo0.hashbang.sh',
            '{ "name": "x", "ssh_keys": ["ssh-dss AAAAB3NzaC1kc3MAAACBAKzH7a5sttExNby1J5UaVkJbmAeRxzLvezj59FdpTp5M9zwxdEY3MI7eM/5Dq9j5/Tnd921ixSJyV0vbFka7iEtr2mqp8D1ndSdmJSUtCONDrMm5CfYwwDXlCrujewR1Lt14rADXUWq1ne9TULmhU+0NlkZu32xs5qr8+r8KvimtAAAAFQCjvNn169//E0D18ZWvHum3lyDM7wAAAIBHHGmi/xBcWEiOge8MmTk6tQLHK4jU3V1uayw6w/Z2ixg3eXniSNYKjrDOD5IhbI4MPoYEXKEpWNWJzoOrl2Vl3uzHgGVJ/npTc2mLyvz59/D+bOD7b+vjqqvUXgkjb8rBikG4yBzdVdhpn+pwGIhU2LIM17iSgkVQwRb989IP9wAAAIAEj6i5ipBOPHlvzoTb5ZHhByIo5ogOD47b0UmEoLoBLG4PLfc6kfT9uXFpLRfqNMbzhsy6H7DgEnZYlK7ne2FeXzwxU8Tzuptx8YdZW1paeKxwxsECT5Z0UliJ3mouruNDpEI2N7rIBcWdD/3ck7EtGbPFgtJt7IarFQiHIVSLQA== usercomment"], "shell": "/usr/bin/zsh" }'::jsonb);
        return assert.ok('End of test.');
    exception
    when check_violation then
        return assert.fail('Unable to insert user.');
    end;
end $$ language plpgsql;

-- Positive test for `goodoptions_key_userdata`:
-- check that users with valid dsa ssh_key userdata can be inserted.
create function unit_tests.goodoptions_key_userdata()
returns test_result as $$
declare message test_result;
begin
    begin
        insert into passwd (name, host, "data") values ('ud4', 'fo0.hashbang.sh',
            '{ "name": "x", "ssh_keys": ["command=\"dump /home\",no-pty,no-port-forwarding ssh-dss AAAAB3NzaC1kc3MAAACBAKzH7a5sttExNby1J5UaVkJbmAeRxzLvezj59FdpTp5M9zwxdEY3MI7eM/5Dq9j5/Tnd921ixSJyV0vbFka7iEtr2mqp8D1ndSdmJSUtCONDrMm5CfYwwDXlCrujewR1Lt14rADXUWq1ne9TULmhU+0NlkZu32xs5qr8+r8KvimtAAAAFQCjvNn169//E0D18ZWvHum3lyDM7wAAAIBHHGmi/xBcWEiOge8MmTk6tQLHK4jU3V1uayw6w/Z2ixg3eXniSNYKjrDOD5IhbI4MPoYEXKEpWNWJzoOrl2Vl3uzHgGVJ/npTc2mLyvz59/D+bOD7b+vjqqvUXgkjb8rBikG4yBzdVdhpn+pwGIhU2LIM17iSgkVQwRb989IP9wAAAIAEj6i5ipBOPHlvzoTb5ZHhByIo5ogOD47b0UmEoLoBLG4PLfc6kfT9uXFpLRfqNMbzhsy6H7DgEnZYlK7ne2FeXzwxU8Tzuptx8YdZW1paeKxwxsECT5Z0UliJ3mouruNDpEI2N7rIBcWdD/3ck7EtGbPFgtJt7IarFQiHIVSLQA== usercomment"], "shell": "/usr/bin/zsh" }'::jsonb);
        return assert.ok('End of test.');
    exception
    when check_violation then
        return assert.fail('Unable to insert user.');
    end;
end $$ language plpgsql;

-- Positive test for `ecdsa_key_userdata`:
-- check that users with valid ecdsa ssh_key userdata can be inserted.
create function unit_tests.ecdsa_key_userdata()
returns test_result as $$
declare message test_result;
begin
    begin
        insert into passwd (name, host, "data") values ('ud5', 'fo0.hashbang.sh',
            '{ "name": "x", "ssh_keys": ["ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF7HJjm4tLwVdpG11KH26cK+K42oUwF3fRFoqgmj0BxtYjhTl/aS4qmB5K9z2mwGXn4ZVEfBnFpXTDBgwXzAvMA= usercomment"], "shell": "/usr/bin/zsh" }'::jsonb);
        return assert.ok('End of test.');
    exception
    when check_violation then
        return assert.fail('Unable to insert user.');
    end;
end $$ language plpgsql;
