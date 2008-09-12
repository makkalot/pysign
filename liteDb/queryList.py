#Data set needed to initialize the
class dbConstants(object):
    """ Includes some vars and queries""" 
    DBNAME='/home/makkalot/workspace/BendeCrypt/src/liteDb/imza' 
    sqlInitCom={
         
         'q1create_chain':'create table chains (\
                        c_id integer not null primary key AUTOINCREMENT,\
                        name varchar(30),\
                        trust_deg text\
                        )',
                        
         'q2create_cert':'create table certs (\
                        ce_id integer not null primary key AUTOINCREMENT,\
                        ch_id integer not null\
                        constraint fk_cid references chains(c_id)\
                        on delete cascade,\
                        cert_data text not null,\
                        cert_sum varchar(40) not null)',
                        
           'q3prevent_insert':'CREATE TRIGGER fki_certs_ch_id_chains_c_id\
                               BEFORE INSERT ON [certs]\
                               FOR EACH ROW BEGIN\
                                   SELECT RAISE(ROLLBACK, \'insert on table \"certs\" violates foreign key constraint \"fki_certs_ch_id_chains_c_id\"\')\
                                   WHERE (SELECT c_id FROM chains WHERE c_id = NEW.ch_id) IS NULL;\
                                   END',
                            
            'q4revent_update':'CREATE TRIGGER fku_certs_ch_id_chains_c_id\
                                BEFORE UPDATE ON [certs]\
                                FOR EACH ROW BEGIN\
                                    SELECT RAISE(ROLLBACK, \'update on table \"certs\" violates foreign key constraint \"fku_certs_ch_id_chains_c_id\"\')\
                                    WHERE (SELECT c_id FROM chains WHERE c_id = NEW.ch_id) IS NULL;\
                                END',
                                
            'q5force_delete':'CREATE TRIGGER fkdc_certs_ch_id_chains_c_id\
                            BEFORE DELETE ON [chains]\
                                FOR EACH ROW BEGIN\
                                DELETE FROM certs WHERE certs.ch_id = OLD.c_id;\
                            END'

           }

#print sqlInitCom['create_chain']
#print sqlInitCom['create_cert']