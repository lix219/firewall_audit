#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/open_db record pass/;

sub ip2num {
    my $ip = shift;
    my @p = split(/\./, $ip);

    return $p[0]* (256 ** 3) + $p[1] * 256 ** 2 + $p[2] * 256 + $p[3];
}

sub num2ip {
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


sub _4205{
    #detect net redundancy in itself
    my $tid=shift;
    my $dbh = open_db;
	my $sign_4205 = 0;		
    my %hash_redun_net = ();

    my $sth=$dbh->prepare("SELECT net_name,net_ip FROM cfg_net WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth->execute() or die $!;

    #my %hash_net = ();
    #my @net_grp;

    while(my @row_ary=$sth->fetchrow_array()){
            my %hash_net = ();
            #print "A@row_ary\n";
            #push @net_grp,$row_ary[0];
            #my @iparr=();
            #my %hash_net=;
            my @arr = split(/\s+/,$row_ary[1]); #array of single ip or range or subnet in present net object
            foreach my $net_ip(@arr){
                #print "test1\n";
                if($net_ip =~ /any/i){  #any
                    if (exists $hash_net{$net_ip}){ 
                        if ( !(exists $hash_redun_net{$row_ary[0]}) ){
                            $hash_redun_net{$row_ary[0]} = 1;
                            pass $tid,4205,'fail',"地址对象$row_ary[0]存在重复ip";
                            $sign_4205=1;
                        }
                    }else{    
                        $hash_net{$net_ip} = 1;
                    }
                    #print "any\n";
                    #push @iparr,1;
                    next;
                }

                if(!($net_ip =~ /-/)){  #singe ip
                    #print "单个ip $net_ip\n";
                    if (exists $hash_net{$net_ip}){ 
                        if ( !(exists $hash_redun_net{$row_ary[0]}) ){
                            $hash_redun_net{$row_ary[0]} = 1;
                            pass $tid,4205,'fail',"地址对象$row_ary[0]存在重复ip";
                            $sign_4205=1;
                        }
                    }else{
                        $hash_net{$net_ip} = 1;
                    }
                    #push (@iparr,$net_ip);                    
                    next;
                }

                if(!($net_ip =~ /</)){
                    if ($net_ip =~ /(.*)-(.*)/) {   #range or subnet without breakpoint
                            
                            my $begin = ip2num($1);
                            my $end = ip2num($2);

                            foreach($begin..$end){ 
                                my $ip_4205 = num2ip($_);
                                if ( exists $hash_net{$ip_4205} ){ 
                                    if ( !(exists $hash_redun_net{$row_ary[0]}) ){
                                        $hash_redun_net{$row_ary[0]} = 1;
                                        pass $tid,4205,'fail',"地址对象$row_ary[0]存在重复ip";
                                        $sign_4205=1;
                                    }
                                }else{
                                    $hash_net{$ip_4205} = 1;
                                }                               
                                #push @iparr,num2ip($_);
                            }
                    }
                    next;
                }

                if($net_ip =~ /(.*)-(.*)<(.*)>/){   #range or subnet with breakpoint
                    my @break_num;
                    my @break_ip=split /:/,$3;

                    foreach my $ip(@break_ip){
                        push @break_num, (ip2num($ip) - 1);
                        push @break_num, (ip2num($ip) + 1);
                    }

                    push @break_num,ip2num($1);
                    push @break_num,ip2num($2);

                    @break_num = sort {$a <=> $b} @break_num;

                    my $a; my $b; 
                    foreach my $p (@break_num) {
                        $i++;
                        if ($i % 2 == 1) {
                        $a = $p;
                        } else {
                            $b = $p; 
                            foreach ($a..$b) {
                                my $ip_4205 = num2ip($_);
                                if ( exists $hash_net{$ip_4205} ){ 
                                    if ( !(exists $hash_redun_net{$row_ary[0]}) ){
                                        $hash_redun_net{$row_ary[0]} = 1;
                                        pass $tid,4205,'fail',"地址对象$row_ary[0]存在重复ip";
                                        $sign_4205=1;
                                    }
                                }else{
                                    $hash_net{$ip_4205} = 1;
                                }  
                                #push @iparr,num2ip($_);   
                            }
                        }
                    }
                    next;   
                }
                next;
            } #foreach net_ip
            #my $n=$#iparr;
            #print "$n\n";
            $hash_net{$row_ary[0]}=\@iparr;
    }  #while        

    

	if($sign_4205 == 0 ){pass $tid,4205,'pass',"地址对象不存在冗余";}
		
    print "ok\n";
    $sth->finish();
}

#_4205 2015;
1
