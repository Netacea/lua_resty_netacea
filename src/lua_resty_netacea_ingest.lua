local Kinesis = require("kinesis_resty")
local Ingest = {}
local utils = require("netacea_utils")
local cjson = require 'cjson'
local ngx = require 'ngx'

local function new_queue(size, allow_wrapping)
  -- Head is next insert, tail is next read
  local head, tail = 1, 1;
  local items = 0; -- Number of stored items
  local t = {}; -- Table to hold items
  return {
    _items = t;
    size = size;
    count = function (_) return items; end;
    push = function (_, item)
      if items >= size then
        if allow_wrapping then
          tail = (tail%size)+1; -- Advance to next oldest item
          items = items - 1;
        else
          return nil, "queue full";
        end
      end
      t[head] = item;
      items = items + 1;
      head = (head%size)+1;
      return true;
    end;
    pop = function (_)
      if items == 0 then
        return nil;
      end
      local item;
      item, t[tail] = t[tail], 0;
      tail = (tail%size)+1;
      items = items - 1;
      return item;
    end;
    peek = function (_)
      if items == 0 then
        return nil;
      end
      return t[tail];
    end;
    items = function (self)
      return function (pos)
        if pos >= t:count() then
          return nil;
        end
        local read_pos = tail + pos;
        if read_pos > t.size then
          read_pos = (read_pos%size);
        end
        return pos+1, t._items[read_pos];
      end, self, 0;
    end;
  };
end


function Ingest:new(options, _N_parent)
    local n = {}
    setmetatable(n, self)
    self.__index = self

    n._N = _N_parent

    n.stream_name = options.stream_name or ''
    n.region = options.region or 'eu-west-1'
    n.aws_access_key = options.aws_access_key or ''
    n.aws_secret_key = options.aws_secret_key or ''

    n.queue_size = options.queue_size or 5000
    n.dead_letter_queue_size = options.dead_letter_queue_size or 1000
    n.batch_size = options.batch_size or 25
    n.batch_timeout = options.batch_timeout or 1.0

    n.data_queue = new_queue(n.queue_size, true);
    n.dead_letter_queue = new_queue(n.dead_letter_queue_size, true);
    n.BATCH_SIZE = n.batch_size; -- Kinesis PutRecords supports up to 500 records, using 25 for more frequent sends
    n.BATCH_TIMEOUT = n.batch_timeout; -- Send batch after 1 second even if not full
    ngx.log( ngx.DEBUG, "NETACEA INGEST - initialized with queue size ", n.queue_size, ", dead letter queue size ", n.dead_letter_queue_size, ", batch size ", n.BATCH_SIZE, ", batch timeout ", n.BATCH_TIMEOUT );
    return n
end
-- Data queue for batch processing


--------------------------------------------------------
-- start batch processor for Kinesis data

function Ingest:start_timers()

  -- start batch processor
  local batch_processor;
  ngx.log( ngx.DEBUG, "NETACEA INGEST - starting batch processor timer" );
  batch_processor = function( premature )

    if premature then return end
    
    local execution_thread = ngx.thread.spawn( function()
      local batch = {}
      local last_send_time = ngx.now()

      while true do
        -- Check if worker is exiting
        if ngx.worker.exiting() == true then 
          -- Send any remaining data before exiting
          if #batch > 0 then
            self:send_batch_to_kinesis(batch)
          end
          return 
        end

        -- ngx.log( ngx.DEBUG, "NETACEA BATCH - checking for data to batch, current queue size: ", self.data_queue:count(), ", dead letter queue size: ", self.dead_letter_queue:count() );

        local current_time = ngx.now()
        local should_send_batch = false
        local dead_letter_items = 0
        -- Check dead_letter_queue first
        while self.dead_letter_queue:count() > 0 and #batch < self.BATCH_SIZE do
          local dlq_item = self.dead_letter_queue:pop()
          if dlq_item then
            table.insert(batch, dlq_item)
            dead_letter_items = dead_letter_items + 1
          end
        end

        if (dead_letter_items > 0) then
          ngx.log(ngx.DEBUG, "NETACEA BATCH - added ", dead_letter_items, " items from dead letter queue to batch")
        end

        -- Collect data items for batch
        while self.data_queue:count() > 0 and #batch < self.BATCH_SIZE do
          local data_item = self.data_queue:pop()
          if data_item then
            table.insert(batch, data_item)
          end
        end

        -- Determine if we should send the batch
        if #batch >= self.BATCH_SIZE then
          should_send_batch = true
          ngx.log(ngx.DEBUG, "NETACEA BATCH - sending full batch of ", #batch, " items")
        elseif #batch > 0 and (current_time - last_send_time) >= self.BATCH_TIMEOUT then
          should_send_batch = true
          ngx.log(ngx.DEBUG, "NETACEA BATCH - sending timeout batch of ", #batch, " items")
        end

        -- Send batch if conditions are met
        if should_send_batch then
          self:send_batch_to_kinesis(batch)
          batch = {}  -- Reset batch
          last_send_time = current_time
        end

        -- Sleep briefly if no data to process
        if self.data_queue:count() == 0 and self.dead_letter_queue:count() == 0 then
          ngx.sleep(0.1)
        end
      end
    end )

    local ok, err = ngx.thread.wait( execution_thread );
    if not ok and err then
      ngx.log( ngx.ERR, "NETACEA - batch processor thread has failed with error: ", err );
    end

    -- If the worker is exiting, don't queue another processor
    if ngx.worker.exiting() then
      return
    end

    ngx.timer.at( 0, batch_processor );
  end

  ngx.timer.at( 0, batch_processor );

end

function Ingest:send_batch_to_kinesis(batch)
  if not batch or #batch == 0 then return end
  
  local client = Kinesis.new(
      self.stream_name,
      self.region,
      self.aws_access_key,
      self.aws_secret_key
  )

  -- Convert batch data to Kinesis records format
  local records = {}
  for _, data_item in ipairs(batch) do
    table.insert(records, {
      partition_key = utils.buildRandomString(10),
      data = "[" .. cjson.encode(data_item) .. "]"
    })
  end

  ngx.log( ngx.DEBUG, "NETACEA BATCH - sending batch of ", #records, " records to Kinesis stream ", self.stream_name );

  local res, err = client:put_records(records)
  if err then
    ngx.log( ngx.ERR, "NETACEA BATCH - error sending batch to Kinesis: ", err );
    for _, data_item in ipairs(batch) do
      local ok, dlq_err = self.dead_letter_queue:push(data_item)
      if not ok and dlq_err then
        ngx.log( ngx.ERR, "NETACEA BATCH - failed to push record to dead letter queue: ", dlq_err );
      end
    end
  else
    ngx.log( ngx.DEBUG, "NETACEA BATCH - successfully sent batch to Kinesis, response status: ", res.status .. ", body: " .. (res.body or '') );
  end

end

function Ingest:ingest()
  local vars = ngx.var
  local mitata = ngx.ctx.mitata or vars.cookie__mitata or ''
  local NetaceaState = ngx.ctx.NetaceaState or {}

  local data = {
    Request = vars.request_method .. " " .. vars.request_uri .. " " .. vars.server_protocol,
    TimeLocal = vars.time_local,
    TimeUnixMsUTC = vars.msec * 1000,
    RealIp = NetaceaState.client or utils:getIpAddress(vars, self._N.realIpHeader),
    UserAgent = vars.http_user_agent or "-",
    Status = vars.status,
    RequestTime = vars.request_time,
    BytesSent = vars.bytes_sent,
    Referer = vars.http_referer or "-",
    NetaceaUserIdCookie = mitata,
    UserId = NetaceaState.UserId or "-",
    NetaceaMitigationApplied = NetaceaState.bc_type,
    IntegrationType = self._N._MODULE_TYPE,
    IntegrationVersion = self._N._MODULE_VERSION,
    Query = vars.query_string or "",
    RequestHost = vars.host or "-",
    RequestId = vars.request_id or "-",
    ProtectionMode = self._N.mitigationType or "ERROR",
    -- TODO
    BytesReceived = vars.bytes_received or 0, -- Doesn't seem to work
    NetaceaUserIdCookieStatus = 1,
    Optional = {}
  }

  -- Add data directly to the queue for batch processing
  local ok, err = self.data_queue:push(data)
  if not ok and err then
    ngx.log(ngx.ERR, "NETACEA INGEST - failed to queue data: ", err)
  else
    ngx.log(ngx.DEBUG, "NETACEA INGEST - queued data item, queue size: ", self.data_queue:count())
  end

end

return Ingest