#!/usr/bin/perl -I /home/fw_audit/script/lib

use DBI;
use strict;
use warnings;
use Redis;
use utf8;

use Firewall::Common qw /record open_redis open_db pass/;
use Firewall::Audit qw /acl_schedule count_dst/;

sub ip2num_3205 {
	my $ip = shift;
	my @p = split(/\./, $ip);

	return $p[0]* (256 ** 3) + $p[1] * 256 ** 2 + $p[2] * 256 + $p[3];
}

sub num2ip_3205 {
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

sub connect_redis_3205 {
	my $handle = Redis->new(server => '10.109.32.166:6379', name => 'what');
	$handle->select(1);

	return $handle;
}


sub compare_acl_policy_3205 {
	my $index1 = shift;
	my $index2 = shift;

	my $acl_policy1 = "acl_policy"."_set_$index1";
	my $acl_policy2 = "acl_policy"."_set_$index2";

	my $redis_handle = connect_redis_3205;
	my @acl_policy_set1 = $redis_handle->smembers($acl_policy1);
	my @acl_policy_set2 = $redis_handle->smembers($acl_policy2);

	my %acl_policy_hash1;
	my %acl_policy_hash2;

	foreach (@acl_policy_set1) {
		$acl_policy_hash1{$_} = 1;
	}

	foreach (@acl_policy_set2) {
		$acl_policy_hash2{$_} = 1;
	}

	foreach (keys %acl_policy_hash1) {
		if (! exists($acl_policy_hash2{$_})) {
print "acl_id $index1 $index2 acl policy different\n";
			$redis_handle->quit;
			return -1;
		}
	}
print "acl_id $index1 $index2 acl policy same\n";
			$redis_handle->quit;
			return 0;
}


sub compare_srv_3205 {
	my $index1 = shift;
	my $index2 = shift;

	my $srv1 = "srv"."_set_$index1";
	my $srv2 = "srv"."_set_$index2";

	my $redis_handle = connect_redis_3205;
	my @srv_set1 = $redis_handle->smembers($srv1);
	my @srv_set2 = $redis_handle->smembers($srv2);

	my %srv_hash1;
	my %srv_hash2;

	foreach (@srv_set1) {
		$srv_hash1{$_} = 1;
	}

	foreach (@srv_set2) {
		$srv_hash2{$_} = 1;
	}

	if ($#srv_set1 != $#srv_set2)	{
print "acl_id $index1 $index2 srv different\n";
		$redis_handle->quit;
		return -1;
	} else {
		foreach (keys %srv_hash1) {
			if (! exists($srv_hash2{$_})) {
print "acl_id $index1 $index2 srv different\n";
				$redis_handle->quit;
				return -1;
			}
		}
	}

print "acl_id $index1 $index2 srv totally same\n";
	$redis_handle->quit;
	return 0;
}

# return 0; show totally same with each other
sub compare_src_addr_3205 {
	my $index1 = shift;
	my $index2 = shift;

	my $src_addr_set1 = "src_addr"."_set_$index1";
	my $src_addr_set2 = "src_addr"."_set_$index2";
	my $interset = "$src_addr_set1"."_$src_addr_set2";

	my $redis_handle = connect_redis_3205;

	my $ret = $redis_handle->sinterstore($interset, $src_addr_set1, $src_addr_set2);

	my $scard_set1 = $redis_handle->scard($src_addr_set1);
	my $scard_set2 = $redis_handle->scard($src_addr_set2);
	my $scard_interset = $redis_handle->scard($interset);

	if ($scard_set1 == $scard_interset and $scard_set2 == $scard_interset) {
		print "acl_id $index1 $index2 src_addr totally same\n";
		$redis_handle->quit;
		return 0;
	}

	print "acl_id $index1 $index2 src_addr different\n";
	$redis_handle->quit;
	return -1;
}


sub inter_dst_addr_3205 {
	my $index1 = shift;
	my $index2 = shift;

	my $dst_addr_set1 = "dst_addr"."_set_$index1";
	my $dst_addr_set2 = "dst_addr"."_set_$index2";
	my $interset = "$dst_addr_set1"."_$dst_addr_set2";

	my $redis_handle = connect_redis_3205;

	my $ret = $redis_handle->sinterstore($interset, $dst_addr_set1, $dst_addr_set2);

	my $scard_set1 = $redis_handle->scard($dst_addr_set1);
	my $scard_set2 = $redis_handle->scard($dst_addr_set2);
	my $scard_interset = $redis_handle->scard($interset);

	if ($scard_interset > 0 and $scard_interset < $scard_set1 and $scard_interset < $scard_set2) {
		print "acl_id $index1 and $index2 have interset in dst_addr\n";
		$redis_handle->quit;
		return 0;
	}

	$redis_handle->quit;
	return -1;
}






sub _3205 {
 	my $task_id = shift;

	my $host = '10.109.32.166';
	my $port = "3306";
	my $user = 'root';
	my $password = '123456';
	my $dbname = 'fw_audit';

	my $redis_handle = connect_redis_3205;

	my $database = "DBI:mysql:$dbname:$host:$port";
	my $dbh = DBI->connect($database, $user, $password);
	$dbh->do("SET NAMES 'utf8'");

 	my $sth = $dbh->prepare("SELECT acl_id, src_addr, dst_addr, srv, acl_policy FROM cfg_acl WHERE task_id = $task_id");
 	$sth->execute() or die "Can't execute: $dbh->errstr";

	my %total_hash;

 	while (my @total_arr  = $sth->fetchrow_array) {
#		print "$#total_arr (acl_id, src_addr, dst_addr, srv, acl_policy )  @total_arr", "\n";
		my @arr; my $i = 0;
		while ($i <= $#total_arr) {
			push @arr, $total_arr[$i];
			$i++;
		}

		$total_hash{$total_arr[0]} = \@arr;
#		print "$total_arr[0]\n";
	}

#		acl_id, src_addr, dst_addr, srv, acl_policy
	foreach my $key (keys %total_hash) {
		my $i = 0;
		my $sign;
		foreach my $item (@{$total_hash{$key}}) {
			if ($i == 0) {
#				print "[SUBJECT] $item\t";
				$sign = $item;
			} elsif ($i == 1) {
				my $src_addr_set = "src_addr"."_set_$sign";
#				print "$src_addr_set $item\t";
				
				my @arr = split(/\s+/, $item);
				foreach my $temp (@arr) {
					if ((my $ret = index("@arr", "any")) != -1) {
						my $ret = $redis_handle->sadd($src_addr_set, 1);
						last;
					}

					if (index($temp, '-') == -1) {
						my $ret = $redis_handle->sadd($src_addr_set, $temp);
					} else {
						if (index($temp, '<') == -1) {
							if ($temp =~ /(.*)-(.*)/) {
								my $begin = ip2num_3205($1);
								my $end = ip2num_3205($2);

								foreach ($begin..$end) {
									my $ret = $redis_handle->sadd($src_addr_set, num2ip_3205($_));
								}
							}
						} else {
							my @break_num;
							my @break_ip;
							if ($temp =~ /(.*)-(.*)<(.*)>/) {
								@break_ip = split /:/, $3;	
							}

							foreach my $ip (@break_ip) {
								push @break_num, (ip2num_3205($ip) - 1);
								push @break_num, (ip2num_3205($ip) + 1);
							}

							push @break_num, ip2num_3205($1);
							push @break_num, ip2num_3205($2);

							@break_num = sort {$a <=> $b} @break_num;

							my $i = 0;
              my $a; my $b; 
              foreach my $p (@break_num) {
                $i++;
                if ($i % 2 == 1) {
                  $a = $p;
                } else {
                  $b = $p; 
									foreach ($a..$b) {
										my $ret = $redis_handle->sadd($src_addr_set, num2ip_3205($_));
									}
                }
							}

						}
					}
				}

			} elsif ($i == 2) {
				my $dst_addr_set = "dst_addr"."_set_$sign";
#				print "$dst_addr_set $item\t";

				my @arr = split(/\s+/, $item);
				foreach my $temp (@arr) {
					my $str = "@arr";
					if ((my $ret1 = index($str, "any")) != -1) {
						my $ret = $redis_handle->sadd($dst_addr_set, 1);
						last;
					}

					if (index($temp, '-') == -1) {
						my $ret = $redis_handle->sadd($dst_addr_set, $temp);
					} else {

						if (index($temp, '<') == -1) {
							if ($temp =~ /(.*)-(.*)/) {
								my $begin = ip2num_3205($1);
								my $end = ip2num_3205($2);

								foreach ($begin..$end) {
									my $ret = $redis_handle->sadd($dst_addr_set, num2ip_3205($_));
								}
							}
						} else {
							my @break_num;
							my @break_ip;
							if ($temp =~ /(.*)-(.*)<(.*)>/) {
								@break_ip = split /:/, $3;	
							}

							foreach my $ip (@break_ip) {
								push @break_num, (ip2num_3205($ip) - 1);
								push @break_num, (ip2num_3205($ip) + 1);
							}

							push @break_num, ip2num_3205($1);
							push @break_num, ip2num_3205($2);

							@break_num = sort {$a <=> $b} @break_num;

							my $i = 0;
              my $a; my $b; 
              foreach my $p (@break_num) {
                $i++;
                if ($i % 2 == 1) {
                  $a = $p;
                } else {
                  $b = $p; 
									foreach ($a..$b) {
										my $ret = $redis_handle->sadd($dst_addr_set, num2ip_3205($_));
									}
                }
							}

						}
					}
				}


			} elsif ($i == 3) {
				my $srv_set = "srv"."_set_$sign";
#				print "$srv_set $item\t";
				my @srv = split /\s+/, $item;
				my $sign = 0;
				foreach my $proto (@srv) {
					if ($proto =~ /any/i) {
						my $ret = $redis_handle->sadd($srv_set, 'any');
						$sign = 1;
					}
				}

				if ($sign == 0) {
					foreach my $proto (@srv) {
						my $ret = $redis_handle->sadd($srv_set, $proto);
					}
				}
			} elsif ($i == 4) {
				my $acl_policy_set = "acl_policy"."_set_$sign";
#				print "$acl_policy_set $item\t";
				my $ret = $redis_handle->sadd($acl_policy_set, $item);
			}
			$i++;
		}
#		print "\n";
	}

	my @array;
	foreach my $key (keys %total_hash) {
		push @array, $key;
	}

	my $j = 0;
	while ($j < $#array) {
		my $k = $j + 1;
		while ($k <= $#array) {
#			print $array[$j], "\t", $array[$k], "\n";
			my $ret1 = compare_src_addr_3205($array[$j], $array[$k]);
			my $ret2 = inter_dst_addr_3205($array[$j], $array[$k]);
			my $ret3 = compare_srv_3205($array[$j], $array[$k]);
			my $ret4 = compare_acl_policy_3205($array[$j], $array[$k]);
			my $ret5 = acl_schedule($task_id, $array[$j], $array[$k]);
			if ($ret1 == 0 and $ret2 == 0 and $ret3 == 0 and $ret4 == 0 and $ret5 ==1) {
				print "\n*****************************\n";
				print "acl_id $array[$j], $array[$k] have interset in dst_addr\n";
				my $sth_dst = count_dst($task_id,$array[$j],$array[$k]);
				pass $task_id, 3205, 'fail', "访问控制策略$array[$j]与$array[$k]之间存在目的地址部分冗余. "."$sth_dst";
				record  3205, "TASK[$task_id] 访问控制策略 $array[$j] 与 $array[$k] 之间存在目的地址部分冗余";
			} else {
#				pass $task_id, 3205, 'pass', "访问控制策略 $array[$j] 与 $array[$k] 之间不存在目的地址部分冗余";
				record  3205, "TASK[$task_id] 访问控制策略 $array[$j] 与 $array[$k] 之间不存在目的地址部分冗余";
			}

			$k++;
		}
		shift @array;
	}

	$redis_handle->flushall;
	$redis_handle->quit;

}

#_3205 9999;
1
