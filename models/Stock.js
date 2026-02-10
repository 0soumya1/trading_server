import mongoose from "mongoose";

const StockSchema = new mongoose.Schema({
  symbol: {
    type: String,
    required: true,
    unquie: true,
  },
  companyName: {
    type: String,
    required: true,
  },
  iconUrl: {
    type: String,
    required: true,
  },
  lastDayTradedPrice: {
    type: Number,
    required: true,
  },
  // lastDayTradedPrice is the price at which the stock was last traded on the previous trading day. This serves as a reference point for investors to understand how the stock has performed since the last trading session.
  currentPrice: {
    type: Number,
    required: true,
  },
  dayTimeSeries: {
    type: [object],
    default: [],
  },
  // dayTimeSeries is an array of objects, where each object represents the stock's price at a specific time during the trading day. This can be used to create intraday price charts or analyze price movements throughout the day.
  tenMinTimeSeries: {
    type: [object],
    default: [],
  },
  // tenMinTimeSeries is an array of objects that captures the stock's price at 10-minute intervals. This provides a more granular view of the stock's price movements during the trading day, which can be useful for short-term traders or for analyzing volatility.
});

const Stock = mongoose.model("Stock", StockSchema);

export default Stock;
