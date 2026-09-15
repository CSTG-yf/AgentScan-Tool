import { theme, type ThemeConfig } from "antd";

// 只负责启用组件库浅色算法；治理页面的视觉样式统一在 governance.css。
export const governanceTheme: ThemeConfig = {
  inherit: false,
  algorithm: theme.defaultAlgorithm,
};
