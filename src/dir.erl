-module(dir).
-include("LDAP.hrl").
-compile(export_all).

init() -> listen(389).

listen(Port) -> 
    {ok,ServerSocket} = 
        gen_tcp:listen(Port,[binary, {packet,0}, {active, false}]),
    spawn(fun() -> accept(ServerSocket) end).

accept(ServerSocket) ->
    {ok,Socket} = gen_tcp:accept(ServerSocket),
    spawn(fun() -> looper(Socket) end),
    accept(ServerSocket).

looper(Socket) ->
    case gen_tcp:recv(Socket,0) of
         {ok,Data} -> Decoded = asn1rt:decode('LDAP','LDAPMessage',Data),
                      case Decoded of 
                           {ok,{'LDAPMessage',No,Message,ASN}} -> 
                                message(No,Message,Socket);
                           _ -> skip end, 
                      looper(Socket);
         _ -> io:format("Stop~n") end.
   
message(No,Message,Socket) ->
    case Message of
         {bindRequest,{'BindRequest',Version,Name,Auth}} -> 
              bind(No,Version,Name,Auth,Socket);
         {searchRequest,{'SearchRequest', BaseDN, Scope, Deref, 
              SizeLimit, TimeLimit, TypesOnly, Filter, Attributes}} ->
              search(No,BaseDN, Scope, Deref, SizeLimit, TimeLimit, 
              TypesOnly, Filter, Attributes, Socket);
         _ -> io:format("Unknown Request~n") end.

bind(No,Version,Name,Auth,Socket) ->
    Response = #'BindResponse'{resultCode = success, matchedDN = Name, 
                               diagnosticMessage = "OK"},
    answer(No,bindResponse,Response,Socket).

search(No,BaseDN, Scope, Deref, SizeLimit, TimeLimit, 
              TypesOnly, Filter, Attributes, Socket) ->
    [ begin Attrs = [ #'PartialAttribute'{type="cn", vals=[Name]},
                      #'PartialAttribute'{type="mail", vals=[Mail]} ],
           Response = #'SearchResultEntry'{objectName=Name,attributes=Attrs},
           answer(No,searchResEntry,Response,Socket) 
     end || {Name,Mail} <- [{"Maxim","ua.fm"}] ],
    Done = #'LDAPResult'{resultCode = success, matchedDN = BaseDN, 
                              diagnosticMessage = "OK"},
    answer(No,searchResDone,Done,Socket).

answer(No,Op,Response,Socket) ->
    Message = #'LDAPMessage'{messageID = No, protocolOp = {Op, Response}},
    {ok,Bytes} = asn1rt:encode('LDAP','LDAPMessage',Message),
    gen_tcp:send(Socket,list_to_binary(Bytes)).
