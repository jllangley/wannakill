##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'set'

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'         => 'Kill and remove WannaCry executables',
      'Description'  => %q{
	This module attempts to kill and delete the processes related to wannacry infections.
      },
      'License'      => MSF_LICENSE,
      'Author'       => [
        'Marc-Andre Meloche (MadmanTM)',
        'Nikhil Mittal (Samratashok)',
        'Jerome Athias',
        'OJ Reeves'
      ],
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter']
    ))
  end

  def skip_process_name?(process_name)
    [
      '[system process]',
      'system'
    ].include?(process_name)
  end

  def run
    avs = ["mssecsvc.exe", "tasksche.exe"]               

    avs = Set.new(avs.split("\n"))

    processes_found = 0
    processes_killed = 0
    client.sys.process.get_processes().each do |x|
      next if skip_process_name?(x['name'].downcase)
      vprint_status("Checking #{x['name'].downcase} ...")
      if avs.include?(x['name'].downcase)
        processes_found += 1
        print_status("Attempting to terminate '#{x['name']}' (PID: #{x['pid']}) ...")
        begin
          client.sys.process.kill(x['pid'])
          processes_killed += 1
          print_good("#{x['name']} terminated.")
	  File.delete("c:\windows\#{x}")
        rescue Rex::Post::Meterpreter::RequestError
          print_error("Failed to terminate '#{x['name']}' (PID: #{x['pid']}).")
        end
      end
    end

    if processes_found == 0
      print_status('No target processes were found.')
    else
      print_good("A total of #{processes_found} process(es) were discovered, #{processes_killed} were terminated.")
    end
    
    if File.exist?('c:\windows\mssecsvc.exe')
      print_status('File NOT deleted!!!!')
    else 
      print_good("mssecsvc deleted successfully!")
    end

    if File.exist?('c:\windows\tasksche.exe')
      print_status('File NOT deleted!!!!')
    else 
      print_good("tasksche deleted successfully!")
    end

  end
end
