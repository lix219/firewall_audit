#!/usr/bin/perl -I /home/fw_audit/script/lib

use DBI;
#use strict;
#use warnings;
#use Redis;

use Firewall::Common qw /record open_redis open_db pass/;


sub ip2num_1 {
	my $ip = shift;
	my @p = split(/\./, $ip);

	return $p[0]* (256 ** 3) + $p[1] * 256 ** 2 + $p[2] * 256 + $p[3];
}

sub num2ip_1 {
	my $num = shift;
	my @ip;
	my $x;
	my $i;

	for($i=0; $i<4; $i++){
	  $x = $num%256;
	  if($x<0) {$x += 256;}
	  unshift(@ip, $x);
	  $num = int($num/256);
  }

  return join('.', @ip);
}


#源ip不含8.8.8.8
sub _4208{
 	my $task_id = shift;
	my $sign = 0;  
 	my $n_ip="8.8.8.8";

	my $host = '10.109.32.166';
	my $port = "3306";
	my $user = 'root';
	my $password = '123456';
	my $dbname = 'fw_audit';

	#my $redis_handle = connect_redis;

	my $database = "DBI:mysql:$dbname:$host:$port";
	my $dbh = DBI->connect($database, $user, $password);
	$dbh->do("SET NAMES 'utf8'");

 	my $sth = $dbh->prepare("SELECT acl_id, src_addr FROM cfg_acl WHERE task_id = $task_id");
 	$sth->execute() or die "Can't execute: $dbh->errstr";

	
 	while(my @row_ary=$sth->fetchrow_array()){
            #print "A@row_ary\n";
            #push @net_grp,$row_ary[0];
            my @iparr=();
            #my %total_hash=;
            my @arr = split(/\s+/,$row_ary[1]); #ip
            foreach my $net_ip(@arr){
                #print "test1\n";
                if($net_ip =~ /any/i){
                    #print "any\n";
                    push @iparr,1;
                    next;
                }

                if(!($net_ip =~ /-/)){
                    #print "单个ip $net_ip\n";
                    push (@iparr,$net_ip);                    
                    next;
                }

                if(!($net_ip =~ /</)){
                    if ($net_ip =~ /(.*)-(.*)/) {
                            
                            my $begin = ip2num_1($1);
                            my $end = ip2num_1($2);

                            foreach($begin..$end){                                
                                push @iparr,num2ip_1($_);
                            }
                    }
                    next;
                }

                if($net_ip =~ /(.*)-(.*)<(.*)>/){
                    my @break_num;
                    my @break_ip=split /:/,$3;

                    foreach my $ip(@break_ip){
                        push @break_num, (ip2num_1($ip) - 1);
                        push @break_num, (ip2num_1($ip) + 1);
                    }

                    push @break_num,ip2num_1($1);
                    push @break_num,ip2num_1($2);

                    @break_num = sort {$a <=> $b} @break_num;

                    my $a; my $b; my $i; 
                    foreach my $p (@break_num) {
                        $i++;
                        if ($i % 2 == 1) {
                        $a = $p;
                        } else {
                            $b = $p; 
                            foreach ($a..$b) {
                                push @iparr,num2ip_1($_);   
                            }
                        }
                    }
                }            
            } #foreach net_ip
            #my $n=$#iparr;
            #print "$n\n";
            #$total_hash{$row_ary[0]}=\@iparr;
           
            foreach my $ip(@iparr){
            	if($ip eq $n_ip){
            		pass $task_id,'4208','fail',"访问控制策略$row_ary[0]源地址包含8.8.8.8";
            		$sign = 1;
            	}
            }
    
    }  #while        

	if($sign == 0){pass $task_id,'4208','pass',"访问控制策略源地址不包含8.8.8.8";}

$sth->finish();
	
#	$redis_handle->flushall;
#	$redis_handle->quit;
}

#_4206 3;
1
