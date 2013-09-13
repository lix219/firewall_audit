#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/record open_db pass/;

sub _1002 {
    #detect manager password
    #pass:password is not weak
    #fail:password is weak
    my $tid = shift;
		my $sign_1002 = 0;
    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT pwd FROM cfg_dev_users WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

    #record 'DBASE', $! unless $sth->execute;

    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
        if($row_ary[0] eq 'weak'){
        pass $tid,1002,'fail',"管理员口令强度为弱";
				$sign_1002 = 1;
        }else{        
  #      pass $tid,1002,'pass',"管理员口令强度不为弱";
        }
    }
		if ($sign_1002 ==0){
        pass $tid,1002,'pass',"管理员口令强度不为弱";
    }
    $sth->finish();
}

#_1002 5;
1
