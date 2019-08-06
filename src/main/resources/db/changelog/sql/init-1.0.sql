INSERT INTO BANKS
VALUES ('2293e2cf-1c54-38cf-9934-6be4e94e60f8', 'Lion', 'Lion', 'Lion Bank Ltd.', '/images/bank/lion.svg',
        'https://api.lion.mlabs.dpc.hu:8243/token', 'https://api.lion.mlabs.dpc.hu:8243/open-banking/v3.1/aisp/v3.1.2',
        'PttPN26uJLQgvRjSrhmh5ShaqZga', 'gUPRoq7QUgkuBkdLIkLc1d6fJhka', 'https://lionfintech.mlabs.dpc.hu/callback',
        'acefintech', 'https://api.lion.mlabs.dpc.hu:8243/authorzize',
        'https://api.lion.mlabs.dpc.hu:8243/open-banking/v3.1/pisp/v3.1.2',
        'http://lion.mlabs.dpc.hu/accessschema/ob');
INSERT INTO USERS
VALUES ('tppuser', '{bcrypt}$2a$10$FgRPdjDFcfxrCzWzVO/mZuWwVEm8CxqRNx4qQAOGVjzh/983lUPJy', TRUE);
INSERT INTO AUTHORITIES
VALUES ('tppuser', 'ROLE_USER');
