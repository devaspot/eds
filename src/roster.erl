-module(roster).
-include("roster.hrl").
-include_lib("stdlib/include/qlc.hrl").
-compile(export_all).
-export([init/1,done/0,put/3,get/1,traverse/1]).

init(FileName) ->
	case ets:info(ram) of
		undefined -> ets:new(ram, [named_table,{keypos,#'ContactRecord'.cn},{write_concurrency,true},{read_concurrency,true}]);
		Else -> ok
	end,
	dets:open_file(disk, [{file, FileName},{keypos,#'ContactRecord'.cn}]),
	ets:from_dets(ram,disk).

traverse(Fun) -> dets:traverse(disk,Fun).

list() -> dets:traverse(disk,fun(C) -> io:format("~p~n",[C]),continue end).

done() ->
	case ets:info(ram) of
		undefined -> ram_empty;
		ElseClearRam -> ets:delete(ram)
	end,
	case dets:info(disk) of
		{error,Reason} -> disk_closed;
		ElseCloseDisk -> Res = dets:close(disk), done
	end.

put(CN,GivenName,EMail) ->
	Contact = #'ContactRecord'{cn = CN, givenName = GivenName, mail = EMail},
	ets:insert(ram, Contact),
	dets:insert(disk, Contact),
	ok.

get(CN) ->
	case ets:lookup(ram,CN) of
		[Contact] -> {ok, Contact};
		[] -> {error,instance}
	end.
