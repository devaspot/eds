-module(eds).
-author('Maxim Sokhatsky <maxim@synrc.com>').
-export([start/0]).                                                              
-compile(export_all).
-include("LDAP.hrl").
-include("roster.hrl").
-define(TCP_OPTIONS, [binary, {packet, 0}, {active, false}, {reuseaddr, true}]).

start() ->
	listen(389).

listen(Port) ->
	{ok, LSocket} = gen_tcp:listen(Port, ?TCP_OPTIONS),
	accept(LSocket).
	                                     
accept(LSocket) ->
	{ok, Socket} = gen_tcp:accept(LSocket),
	spawn(fun() -> loop(Socket) end),
	accept(LSocket).

loop(Socket) ->
	case gen_tcp:recv(Socket, 0) of
		{ok, Data} ->
			Decoded = asn1rt:decode('LDAP','LDAPMessage',Data),
			io:format("Decoded: ~p~n",[Decoded]),
			case Decoded of
				{ok,{'LDAPMessage',No,Message,Asn}} -> message(No,Message,Socket);
				_Else -> noLDAP
			end,
			loop(Socket);
		{error, closed} ->
			ok
	end.

message(No,Message,Socket) ->
	case Message of
		{bindRequest, {'BindRequest',Type,Uid,Auth}} -> bind(No,Uid,Auth,Socket);
		{abandonRequest,Type} -> abandon(No,Socket);
		{unbindRequest, Null} -> abandon(0,Socket);
		{searchRequest,	{'SearchRequest',SearchDN,Scope,Deref,SizeLimit,
			TimeLimit,TypesOnly,Filter,Attributes}} -> search(No, SearchDN, Scope,Deref,SizeLimit,
			TimeLimit,TypesOnly, Filter,Attributes,Socket);
		_Else -> 
			io:format("~p~n",[Message])
	end.

bind(No,Uid,Auth,Socket) ->
	roster:init(Uid),
	Response = #'BindResponse'{resultCode = success, matchedDN = Uid, diagnosticMessage = "OK"},
	answer(Response,No,bindResponse,Socket).

answer(Response,No,ProtocolOp,Socket) ->
	Message = #'LDAPMessage'{messageID = No, protocolOp = {ProtocolOp, Response}},
	{ok, Bytes} = asn1rt:encode('LDAP', 'LDAPMessage', Message),
	io:format("~p~n", [Message]),
	gen_tcp:send(Socket, list_to_binary(Bytes)).

search(No,SearchDN,Scope,Deref,SizeLimit,TimeLimit,TypesOnly,Filter,Attributes,Socket) ->
	roster:traverse(fun({'ContactRecord',CommonName,GivenName,Mail}) -> 
		CN = {'PartialAttribute', "cn", [CommonName]},
		MAIL = {'PartialAttribute', "mail", [Mail]},
		Response = {'SearchResultEntry', CommonName, [CN,MAIL]},
		answer(Response,No,searchResEntry,Socket),
		continue
	end),
	Done = #'LDAPResult'{resultCode = success, matchedDN = SearchDN, diagnosticMessage = "OK"},
	answer(Done,No,searchResDone,Socket).

abandon(No,Socket) ->
	roster:done(),
	gen_tcp:close(Socket).
