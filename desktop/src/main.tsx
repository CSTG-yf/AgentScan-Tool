import React from "react";
import ReactDOM from "react-dom/client";
import { ConfigProvider, theme } from "antd";
import zhCN from "antd/locale/zh_CN";
import App from "./App";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: "#44d7b6",
          colorInfo: "#5aa9ff",
          colorBgBase: "#07111e",
          colorBgContainer: "#0d1a29",
          borderRadius: 12,
          fontFamily: "Inter, 'Segoe UI', 'Microsoft YaHei UI', sans-serif",
        },
      }}
    >
      <App />
    </ConfigProvider>
  </React.StrictMode>,
);
