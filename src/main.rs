use serde::{Serialize, Deserialize};

use serde_json::Value;

use chrono::Utc;

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

use reqwest::blocking::Client;

use dotenv::dotenv;

use comfy_table::{Row};


use std::{ env, fs};
use std::thread::sleep;
use std::time::{Duration};
use std::{borrow::Borrow, cmp::Ordering, collections::HashMap};


const BASE_URL_API:&str = "https://api.bybit.com/v5/market/kline";
const URL_FOR_ACTIVE: &str = "https://api.bybit.com/v5/market/instruments-info";


#[derive(Debug, Deserialize)]
struct SheetValues {
    range: Option<String>,
    majorDimension: Option<String>,
    values: Option<Vec<Vec<String>>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: usize,
    iat: usize,
}

#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
}

#[derive(Debug, Clone, Deserialize)]
struct LeverageFilter {
    minLeverage: String,
    maxLeverage: String,
    leverageStep: String,
}

#[derive(Debug, Deserialize)]
struct Instrument {
    symbol: String,
    status: String,
    baseCoin: Option<String>,
    quoteCoin: Option<String>,
    leverageFilter: Option<LeverageFilter>,
}


#[derive(Debug, Deserialize)]
struct ResultData {
    list: Vec<Instrument>,
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    retCode: i32,
    retMsg: String,
    result: Option<ResultData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Data_to_Table {
    name: String,
    diff: f64,
    persent_for_diff: f64,
    amount: f64,
    schoulder: f64,
    persent_to_buy: f64,
    persent_to_sell: f64,
}

struct Clients_data {
    persent_to_buy: f64,
    amount: f64,
    schoulder: f64,
    fixation_persent: f64,
    stop_percentage: f64,
}

#[derive(Debug, Clone)]
struct Candle {
    open: f64,
    high: f64,
    low: f64,
    close: f64,
    volume: f64,
    timestamp: i64,
}


#[derive(Debug, Clone)]
struct Candles {
    candles: Vec<Candle>,
    timeframe: u8,
}


impl Candles {
    ///Получаем реальные свечи с bybit
    ///TODO вытащить максимально возможное плечо
    fn get_real_candles(category: &str, symbol: &str, interval: &str, limit: &str, timeframe: u8) -> Result<Self, Box<dyn std::error::Error>> { 
        let client = reqwest::blocking::Client::new(); 
        let mut params = std::collections::HashMap::new(); 
        
        params.insert("category", category); 
        params.insert("symbol", symbol); 
        params.insert("interval", interval); 
        params.insert("limit", limit); 
        
        let response = client .get(BASE_URL_API) 
            .query(&params) 
            .send()?; 

        let response_text = response.text()?; 

        //TODO добавить проверку, что ответ адекватный - не пустой, не битый и так далее 

        Ok(Self::parse_candles(&response_text, timeframe)?) 
    } 

    ///Парсим ответ bybit в свечи
    fn parse_candles(response: &str, timeframe: u8) -> Result<Self, Box<dyn std::error::Error>> { 
        let json: Value = serde_json::from_str(response)?; 

        if json["retCode"] != 0 { 
            return Err(format!("API Error: {}", json["retMsg"]).into()); 
        } 

        let candles_list = json["result"]["list"] 
            .as_array() 
            .ok_or("Invalid 'list' format in response")?; 

        let mut candles: Vec<Candle> = Vec::new(); 

        for candles_data in candles_list { 
            let data = candles_data 
                .as_array() 
                .ok_or("Invalid candle format")?; 

            if data.len() < 7 { 
                return Err(format!("Invalid candle data: expected 7 elements, got {}", data.len()).into()); 
            } 

            let candle = Candle { 
                open: data[1].as_str().ok_or("Invalid open")?.parse()?, 
                high: data[2].as_str().ok_or("Invalid high")?.parse()?, 
                low: data[3].as_str().ok_or("Invalid low")?.parse()?, 
                close: data[4].as_str().ok_or("Invalid close")?.parse()?, 
                volume: data[5].as_str().ok_or("Invalid volume")?.parse()?, 
                timestamp: data[0].as_str().ok_or("Invalid timestamp")?.parse()?, 
            }; 

            candles.push(candle); 
        } 

        Ok( Candles{ candles, timeframe } ) 
    }
}


///По сути бесполезная структура
impl Data_to_Table {
    fn new(name: String, diff: f64, persent_for_diff: f64, amount: f64, schoulder: f64, persent_to_buy: f64, persent_to_sell: f64) -> Self {
        Self {
            name,
            diff,
            persent_for_diff,
            amount,
            schoulder,
            persent_to_buy,
            persent_to_sell
        }
    }

    fn to_row(&self) -> Row {
        Row::from(Self::to_str(&self))
    }

    fn to_str(&self) -> Vec<String> {
        vec![
            self.name.clone(),
            self.diff.to_string(),
            self.persent_for_diff.to_string(),
            self.amount.to_string(),
            self.schoulder.to_string(),
            self.persent_to_buy.to_string(),
            self.persent_to_sell.to_string(),
        ]
    }
}


impl Clients_data {
    ///Получить данные от клиетна для данной валюты и для (минимального, максимального и шага) плеча
    fn get_data_to_currentpercent(coin: String, diff: f64, schoulder: LeverageFilter, spreadsheet_id: &str, token: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = read_sheet(spreadsheet_id, token, "A2::F1000")?;

        let values = data.values.unwrap_or_default();

        if let Some(row) = values.into_iter().find(|row| {
            row.get(0).map(|c| *c == coin).unwrap_or(false) &&
            row.get(1)
                .and_then(|v| v.parse::<f64>().ok())
                .map(|v| diff >= v)
                .unwrap_or(false)
        }) {
            Ok(Clients_data {
                persent_to_buy: row.get(1).and_then(|v| v.parse::<f64>().ok()).unwrap_or(1.5),
                amount: row.get(2).and_then(|v| v.parse::<f64>().ok()).unwrap_or(100.0),
                schoulder: row.get(3).and_then(|v| v.parse::<f64>().ok()).unwrap_or(35.0),
                fixation_persent: row.get(4).and_then(|v| v.parse::<f64>().ok()).unwrap_or(4.0),
                stop_percentage: row.get(5).and_then(|v| v.parse::<f64>().ok()).unwrap_or(2.0),
            })
        } else {
            Ok(Clients_data {
                persent_to_buy: 1.5,
                amount: 100.0,
                schoulder: 35.0,
                fixation_persent: 4.0,
                stop_percentage: 2.0,
            })
        }
    }
}


///Подписываем токен
fn get_token(sa_key: &ServiceAccountKey) -> Result<String, Box<dyn std::error::Error>> {
    // текущее время
    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + chrono::Duration::hours(1)).timestamp() as usize;

    // формируем claims
    let claims = Claims {
        iss: sa_key.client_email.clone(),
        scope: "https://www.googleapis.com/auth/spreadsheets".to_string(),
        aud: "https://oauth2.googleapis.com/token".to_string(),
        exp,
        iat,
    };

    // JWT header
    let header = Header::new(Algorithm::RS256);

    // создаём ключ из private_key
    let key = EncodingKey::from_rsa_pem(sa_key.private_key.as_bytes())?;

    // кодируем JWT
    let jwt = encode(&header, &claims, &key)?;

    // отправляем в Google
    let client = Client::new();
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", &jwt),
    ];

    let resp: TokenResponse = client
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()?
        .json()?;

    Ok(resp.access_token)
}


///Получаем свечи, которые не учитываем
fn get_coins_not_count(data: &Option<Vec<Vec<String>>>) -> Vec<String> {
    if let Some(data) = data {
        let result = data
            .into_iter()
            .filter_map(|row| {
                if row.len() == 1 {
                    Some(row[0].clone())
                } else {
                    None
                }
            })
            .collect();
        
        return result;
    } else {
        return Vec::new();
    }
}


///Получаем активные свечи с bybit
fn get_active_coin() -> Result<HashMap<String, LeverageFilter>, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::new();

    let mut params = std::collections::HashMap::new();

    params.insert("category", "spot");

    let resp = client
        .get(URL_FOR_ACTIVE)
        .query(&params)
        .send()?
        .text()?;

    let data: ApiResponse = serde_json::from_str(&resp)?;

    if data.retCode != 0 { 
        eprintln!("API error: {}", data.retMsg); 
        Err::<Vec<String>, std::string::String>(data.retMsg); 
    } 

    let output: HashMap<String, LeverageFilter> = data.result
        .unwrap()
        .list
        .iter()
        .filter(|x| x.status == "Trading" && x.quoteCoin.as_deref() == Some("USDT")).map({
            |x| (
                x.symbol.clone(), 
                x.leverageFilter
                    .clone()
                    .unwrap_or(
                        LeverageFilter { 
                            minLeverage: "1".to_string(), 
                            maxLeverage: "1".to_string(), 
                            leverageStep: "0".to_string(), 
                        }
                    )
            )
        }
        ).collect();

    Ok(output)
}


///Прочитать значение таблицы
fn read_sheet(spreadsheet_id: &str, token: &str, range: &str) -> Result<SheetValues, Box<dyn std::error::Error>> {
    let url = format!(
        "https://sheets.googleapis.com/v4/spreadsheets/{}/values/{}!{}",
        spreadsheet_id,
        "Лист2",
        range
    );

    let client = Client::new();
    let resp: SheetValues = client
        .get(&url)
        .bearer_auth(token)
        .send()?
        .json()?;

    Ok(resp)
}

///добавить элемент в таблицу
fn add_elements(spreadsheet_id: &str, token: &str, range: &str, values: &Vec<Vec<String>>) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!(
        "https://sheets.googleapis.com/v4/spreadsheets/{}/values/Лист1!{}?valueInputOption=RAW",
        spreadsheet_id,
        range
    );

    let body = serde_json::json!({
        "range": format!("Лист1!{}", range),
        "majorDimension": "ROWS",
        "values": values,
    });

    let client = Client::new();
    let resp = client
        .put(&url)
        .bearer_auth(token)
        .json(&body)
        .send()?
        .text()?;

    Ok(())
}


///Считаем увеличение цены
fn calculate_grows_rate(coins: &Vec<String>, n: usize) -> Result<Vec<(String, f64)>, Box<dyn std::error::Error>> {
    let mut vec_pct: Vec<(String, f64)> = Vec::new();

    for coin in coins {
        sleep(Duration::from_millis(60));

        let candles = Candles::get_real_candles("spot", coin, "1", "5", 1)?;

        if candles.candles.len() != 0 {
            let first_open = candles.candles.first().unwrap().open;
            let last_close = candles.candles.last().unwrap().close;

            let diff = (last_close - first_open) / first_open * 100.0;

            vec_pct.push((coin.clone(), diff));
        }
    }

    // сортируем по проценту убывания (лучшие сверху)
    vec_pct.sort_by(|a, b| {
        match b.1.partial_cmp(&a.1) {
            Some(ord) => ord,
            None => Ordering::Equal,
        }
    });

    // урезаем до n
    vec_pct.truncate(n);


    Ok(vec_pct)
}


///Функция отправки ордера на bybit
///В данный момент заглушка
fn send_order(coin: String, amount: f64, schoulder: f64, sell: f64, stop: f64) {
    println!("Отправляем ордер для {coin}");
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let data = fs::read_to_string("service_account.json")?;
    let sa_key: ServiceAccountKey = serde_json::from_str(&data)?;

    // получаем access_token
    let token = get_token(&sa_key)?;
    
    let spreadsheet_id = env::var("SPREADSHEET_ID").expect("SpreadSheet_ID must be set");

    let client_data = read_sheet(&spreadsheet_id, &token, "A2:F1000")?;
    
    //Получаем активные монеты
    let data = get_active_coin()?;

    //Активные монеты
    let active_coins: Vec<String> = data.keys().cloned().collect();
    
    //Монеты, которые не учитываем
    let coins_not_count = get_coins_not_count(&client_data.values);
    
    //убираем из активных монет, те, которые не учитываем
    let set: std::collections::HashSet<_> = coins_not_count.into_iter().collect();
    let coins: Vec<_> = active_coins.into_iter().filter(|x| !set.contains(x)).collect();

    //Считаем изменение цены(30 лучших)
    let coins_growth_rate: Vec<(String, f64)> = calculate_grows_rate(&coins, 30)?;

    let mut res: Vec<Data_to_Table> = Vec::new();

    //собираем таблицу
    for (coin, diff) in &coins_growth_rate {
        let client_data = Clients_data::get_data_to_currentpercent(coin.clone(), *diff, data[coin].clone(), &spreadsheet_id, &token)?;

        if *diff >= client_data.persent_to_buy {
            send_order(coin.clone(), client_data.amount, client_data.schoulder, client_data.fixation_persent, client_data.stop_percentage);
        }

        let t = Data_to_Table::new(coin.clone(), *diff, client_data.persent_to_buy, client_data.amount, client_data.schoulder, client_data.fixation_persent, client_data.stop_percentage);
   
        res.push(t);
    }

    //Превращаем в данные для отправки в таблицу
    let table_str: Vec<Vec<String>> = res.iter().map(|row| row.to_str()).collect();

    //Отправляем заголовки
    add_elements(
        &spreadsheet_id, 
        &token, 
        "A1:G1",
        &vec![vec![
            "coin".to_string(), 
            "diff in %".to_string(), 
            "% for column 2".to_string(), 
            "amount".to_string(), 
            "schoulder".to_string(), 
            "TP %".to_string(), 
            "SL %".to_string()
    ]]);

    //Отправляем само содержимое таблицы
    add_elements(&spreadsheet_id, &token, "A2:G31", &table_str)?;

    Ok(())
}
