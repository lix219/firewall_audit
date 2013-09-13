#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/open_db record pass/;

#检测telnet是否开启，规则编号2000
sub _2000 {

   #2000:detect telnet status
    #pass 2000:telnet on
    #fail 2000:telnet off
    
    my $tid=shift;
		my $sign_2000 = 0;

    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT srv_status FROM cfg_srv WHERE srv_type=0 and task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
            
     #		print "@row_ary\n";

     #		pass $tid, 2000,'pass', "telnet远程连接未开启" if $row_ary[0] == 0;
        if($row_ary[0]==1){
						pass $tid, 2000,'fail', "telnet远程连接开启" if $row_ary[0] == 1;     
						$sign_2000 = 1;
				}

    }
    if ($sign_2000 ==0){
        pass $tid, 2000,'pass', "telnet远程连接未开启" if $row_ary[0] == 0;
		}
    print "OK\n";
    $sth->finish();
}

#_2000 99513;
1
