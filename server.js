//-------------------------------------------------------------------
// DAILY STATS UPDATE (uses custom day anchor)
//-------------------------------------------------------------------
void UpdateDailyStats()
{
   datetime now = TimeCurrent();
   datetime day_anchor = DayWindowStart(now);

   if(g_current_day != day_anchor)
   {
      g_current_day = day_anchor;
      g_day_equity_start = GetEquity();
      g_day_equity_peak  = GetEquity();
      g_daily_loss_hit = false;
      g_daily_profit_cap_hit = false;
      g_daily_safe_day_hit = false;

      RebuildRiskTodayClosedPLFromHistory();
      SaveDailyStateToGV();
   }
   else
   {
      double eq = GetEquity();
      if(eq > g_day_equity_peak) g_day_equity_peak = eq;
      SaveDailyStateToGV();
   }
}

//-------------------------------------------------------------------
// POSITIONS
//-------------------------------------------------------------------
bool HasOpenPosition()
{
   for(int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong ticket = PositionGetTicket(i);
      if(!PositionSelectByTicket(ticket)) continue;

      string sym   = PositionGetString(POSITION_SYMBOL);
      long   magic = PositionGetInteger(POSITION_MAGIC);

      if(sym == _Symbol && magic == InpMagicNumber) return true;
   }
   return false;
}

void CloseAllPositionsForSymbol()
{
   for(int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong ticket = PositionGetTicket(i);
      if(!PositionSelectByTicket(ticket)) continue;

      string sym   = PositionGetString(POSITION_SYMBOL);
      long   magic = PositionGetInteger(POSITION_MAGIC);

      if(sym == _Symbol && magic == InpMagicNumber)
         trade.PositionClose(ticket, (ulong)InpSlippage);
   }
}

//-------------------------------------------------------------------
// DAILY LOSS PROTECTION (equity drawdown from peak)
//-------------------------------------------------------------------
double GetDailyLossLimitAmount()
{
   double acc_size = GetConfiguredAccountSize();
   if(acc_size <= 0.0) acc_size = GetBalance();

   if(InpDailyLossFixedAmount > 0.0) return InpDailyLossFixedAmount;
   return acc_size * InpDailyLossPercent / 100.0;
}

bool CheckDailyLossLimit()
{
   if(!InpUseDailyLossProtection) return false;

   double limit = GetDailyLossLimitAmount();
   double eq = GetEquity();
   double drawdown = g_day_equity_peak - eq;

   if(drawdown >= limit && !g_daily_loss_hit)
   {
      if(InpCloseAllOnDailyLoss) CloseAllPositionsForSymbol();
      g_daily_loss_hit = true;
      SaveDailyStateToGV();
   }

   if(g_daily_loss_hit && InpBlockTradingAfterLoss) return true;
   return false;
}

//-------------------------------------------------------------------
// DAILY PROFIT CAP (closed-deals net for day window)
//-------------------------------------------------------------------
double GetDailyProfitCapAmount()
{
   double acc_size = GetConfiguredAccountSize();
   if(acc_size <= 0.0) acc_size = GetBalance();

   if(InpDailyProfitFixedCap > 0.0) return InpDailyProfitFixedCap;
   return acc_size * InpDailyProfitPercentCap / 100.0;
}

bool CheckDailyProfitCap()
{
   if(!InpUseDailyProfitCap) return false;

   double cap = GetDailyProfitCapAmount();
   double net_today = g_risk_today_profit - g_risk_today_loss;

   if(net_today >= cap) g_daily_profit_cap_hit = true;
   SaveDailyStateToGV();
   return g_daily_profit_cap_hit;
}

//-------------------------------------------------------------------
// SAFE/DAY STOP (keeps trading until you CLEAR safe_day + buffer)
//-------------------------------------------------------------------
double GetSafeDayTarget()
{
   double target = GetHUDTargetAmount();
   if(target <= 0.0) return 0.0;
   return target / 5.0;
}

bool CheckSafeDayStop()
{
   if(!InpStopAfterSafeDayHit) return false;

   double safe = GetSafeDayTarget();
   if(safe <= 0.0) return false;

   double buffer = InpSafeDayBufferAmount;
   if(buffer < 0.0) buffer = 0.0;

   double required = safe + buffer;

   double net_today = g_risk_today_profit - g_risk_today_loss;

   if(net_today >= required)
   {
      g_daily_safe_day_hit = true;
      SaveDailyStateToGV();
      return true;
   }

   return false;
}

//-------------------------------------------------------------------
// ROLLOVER / WEEKEND / SPREAD
//-------------------------------------------------------------------
bool IsInRolloverBlock()
{
   if(!InpUseRolloverBlock) return false;

   datetime now = TimeCurrent();
   MqlDateTime st; TimeToStruct(now, st);

   int minutes = st.hour * 60 + st.min;
   int day_minutes = 24 * 60;

   int before = InpNoTradeMinutesBeforeMidnight;
   int after  = InpNoTradeMinutesAfterMidnight;

   if(before < 0) before = 0;
   if(after  < 0) after  = 0;
   if(before > day_minutes) before = day_minutes;
   if(after  > day_minutes) after  = day_minutes;

   if(minutes >= day_minutes - before || minutes < after) return true;
   return false;
}

bool WeekendBlock()
{
   if(!InpUseWeekendProtection) return false;

   datetime now = TimeCurrent();
   MqlDateTime st; TimeToStruct(now, st);

   int dow = st.day_of_week;
   int minutes = st.hour * 60 + st.min;
   int day_mins = 24 * 60;

   if(dow == 6) return true; // Saturday

   if(dow == 5) // Friday
   {
      int block_before = InpFridayNoNewTradeMinutesBeforeMidnight;
      int close_before = InpFridayCloseMinutesBeforeMidnight;

      if(block_before < 0) block_before = 0;
      if(close_before < 0) close_before = 0;
      if(block_before > day_mins) block_before = day_mins;
      if(close_before > day_mins) close_before = day_mins;

      if(minutes >= day_mins - close_before)
      {
         CloseAllPositionsForSymbol();
         return true;
      }

      if(minutes >= day_mins - block_before) return true;
   }

   return false;
}

bool IsSpreadTooHigh()
{
   if(!InpUseMaxSpreadFilter) return false;

   double pip = PipSize();
   if(pip <= 0.0) return false;

   double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);
   double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);

   double spread_pips = (ask - bid) / pip;
   return (spread_pips > InpMaxSpreadPips);
}

//-------------------------------------------------------------------
// STOP-LOSS HELPERS (hard SL + enforce if missing)
//-------------------------------------------------------------------
double MinStopDistancePrice()
{
   int stops_level_points = (int)SymbolInfoInteger(_Symbol, SYMBOL_TRADE_STOPS_LEVEL);
   if(stops_level_points < 0) stops_level_points = 0;
   return (double)stops_level_points * _Point;
}

double CalcHardSLPrice(const bool is_buy, const double entry_price)
{
   double pip = PipSize();
   double dist = InpTrailingStopPips * pip;
   double min_dist = MinStopDistancePrice();

   if(dist <= 0.0) dist = min_dist;

   if(is_buy)
   {
      double sl = entry_price - dist;
      if(min_dist > 0.0 && (entry_price - sl) < min_dist) sl = entry_price - min_dist;
      return sl;
   }
   else
   {
      double sl = entry_price + dist;
      if(min_dist > 0.0 && (sl - entry_price) < min_dist) sl = entry_price + min_dist;
      return sl;
   }
}

void EnforceHardSLIfMissing()
{
   if(!InpUseHardStopAtEntry) return;
   if(InpTrailingStopPips <= 0.0) return;

   double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);
   double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);

   for(int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong ticket = PositionGetTicket(i);
      if(!PositionSelectByTicket(ticket)) continue;

      string sym = PositionGetString(POSITION_SYMBOL);
      long magic = PositionGetInteger(POSITION_MAGIC);
      if(sym != _Symbol || magic != InpMagicNumber) continue;

      long type = PositionGetInteger(POSITION_TYPE);
      double cur_sl= PositionGetDouble(POSITION_SL);
      double cur_tp= PositionGetDouble(POSITION_TP);

      if(cur_sl > 0.0) continue;

      trade.SetExpertMagicNumber(InpMagicNumber);
      trade.SetDeviationInPoints(InpSlippage);

      if(type == POSITION_TYPE_BUY)
      {
         double sl = CalcHardSLPrice(true, ask);
         trade.PositionModify(sym, sl, cur_tp);
      }
      else if(type == POSITION_TYPE_SELL)
      {
         double sl = CalcHardSLPrice(false, bid);
         trade.PositionModify(sym, sl, cur_tp);
      }
   }
}

//-------------------------------------------------------------------
// TRAILING STOP
//-------------------------------------------------------------------
void ApplyTrailingStop()
{
   if(InpTrailingStopPips <= 0.0) return;

   double pip = PipSize();
   double trail_dist = InpTrailingStopPips * pip;
   double min_stop_distance = MinStopDistancePrice();

   double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);
   double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);

   for(int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong ticket = PositionGetTicket(i);
      if(!PositionSelectByTicket(ticket)) continue;

      string sym = PositionGetString(POSITION_SYMBOL);
      long magic = PositionGetInteger(POSITION_MAGIC);
      if(sym != _Symbol || magic != InpMagicNumber) continue;

      long type = PositionGetInteger(POSITION_TYPE);
      double cur_sl= PositionGetDouble(POSITION_SL);
      double cur_tp= PositionGetDouble(POSITION_TP);

      trade.SetExpertMagicNumber(InpMagicNumber);
      trade.SetDeviationInPoints(InpSlippage);

      if(type == POSITION_TYPE_BUY)
      {
         double desired_sl = bid - trail_dist;
         if(min_stop_distance > 0.0 && (bid - desired_sl) < min_stop_distance) desired_sl = bid - min_stop_distance;

         if(cur_sl <= 0.0 || desired_sl > cur_sl)
            trade.PositionModify(sym, desired_sl, cur_tp);
      }
      else if(type == POSITION_TYPE_SELL)
      {
         double desired_sl = ask + trail_dist;
         if(min_stop_distance > 0.0 && (desired_sl - ask) < min_stop_distance) desired_sl = ask + min_stop_distance;

         if(cur_sl <= 0.0 || desired_sl < cur_sl)
            trade.PositionModify(sym, desired_sl, cur_tp);
      }
   }
}

//-------------------------------------------------------------------
// MT5 EVENT (on any deal, rebuild today's closed P/L for risk vars)
//-------------------------------------------------------------------
void OnTradeTransaction(const MqlTradeTransaction &trans, const MqlTradeRequest &request, const MqlTradeResult &result)
{
   if(trans.type != TRADE_TRANSACTION_DEAL_ADD) return;
   RebuildRiskTodayClosedPLFromHistory();
   DrawDailyHUD();
}

//-------------------------------------------------------------------
// TIMER (prevents HUD freezing / disappearing)
//-------------------------------------------------------------------
void OnTimer()
{
   UpdateDailyStats();
   DrawDailyHUD();

   // license polling (ADD-ONLY)
   if(InpUseLicenseEnforcement)
      LicenseAllowedForNewTrades(); // updates cached state
}

//-------------------------------------------------------------------
// INIT / DEINIT
//-------------------------------------------------------------------
int OnInit()
{
   current_bar_time = iTime(_Symbol, PERIOD_CURRENT, 0);
   trade_opened_this_bar = HasOpenPosition();

   LoadDailyStateFromGV();

   // Ensure baseline exists and reset behavior is safe
   GetBaselineValue();

   // Load + initial license check (ADD-ONLY)
   LoadLicenseStateFromGV();
   if(InpUseLicenseEnforcement)
      LicenseCheckNow();

   UpdateDailyStats();
   RebuildRiskTodayClosedPLFromHistory();
   DrawDailyHUD();

   EventSetTimer(1);
   return(INIT_SUCCEEDED);
}

void OnDeinit(const int reason)
{
   EventKillTimer();
   RemoveHUD();
}

//-------------------------------------------------------------------
// TICK
//-------------------------------------------------------------------
void OnTick()
{
   UpdateDailyStats();
   DrawDailyHUD();

   if(HasOpenPosition())
   {
      EnforceHardSLIfMissing();
      ApplyTrailingStop();
   }

   // Hard blocks
   if(CheckDailyLossLimit()) return;

   // If safe/day already hit, stop for day (and close any open)
   if(g_daily_safe_day_hit || CheckSafeDayStop())
   {
      if(HasOpenPosition()) CloseAllPositionsForSymbol();
      return;
   }

   // Profit cap block (stronger than safe/day)
   if(CheckDailyProfitCap())
   {
      if(HasOpenPosition()) CloseAllPositionsForSymbol();
      return;
   }

   if(WeekendBlock()) return;
   if(IsInRolloverBlock()) return;
   if(IsSpreadTooHigh()) return;

   datetime bar_time = iTime(_Symbol, PERIOD_CURRENT, 0);

   if(bar_time != current_bar_time)
   {
      // Close trade at candle close (on new bar)
      if(HasOpenPosition()) CloseAllPositionsForSymbol();

      current_bar_time = bar_time;
      trade_opened_this_bar = false;

      double prev_open  = iOpen(_Symbol, PERIOD_CURRENT, 1);
      double prev_close = iClose(_Symbol, PERIOD_CURRENT, 1);

      double tol = PipSize() * 0.1;
      if(MathAbs(prev_close - prev_open) <= tol) return;

      if(HasOpenPosition()) return;
      if(trade_opened_this_bar) return;

      // LICENSE SOFT-LOCK (ADD-ONLY) => blocks NEW trades only
      if(!LicenseAllowedForNewTrades())
         return;

      trade.SetExpertMagicNumber(InpMagicNumber);
      trade.SetDeviationInPoints(InpSlippage);

      if(prev_close > prev_open)
      {
         double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);
         double sl = 0.0;
         if(InpUseHardStopAtEntry && InpTrailingStopPips > 0.0)
            sl = CalcHardSLPrice(true, ask);

         if(trade.Buy(InpLots, _Symbol, ask, sl, 0.0, "CandleByCandle BUY"))
         {
            if(trade.ResultRetcode() == TRADE_RETCODE_DONE)
               trade_opened_this_bar = true;
         }
         return;
      }

      if(prev_close < prev_open)
      {
         double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);
         double sl = 0.0;
         if(InpUseHardStopAtEntry && InpTrailingStopPips > 0.0)
            sl = CalcHardSLPrice(false, bid);

         if(trade.Sell(InpLots, _Symbol, bid, sl, 0.0, "CandleByCandle SELL"))
         {
            if(trade.ResultRetcode() == TRADE_RETCODE_DONE)
               trade_opened_this_bar = true;
         }
         return;
      }
   }
}
//+------------------------------------------------------------------+
